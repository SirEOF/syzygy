// Axel '0vercl0k' Souchet 20 April 2017
#include "syzygy/instrument/transforms/security_cookie_check_hook_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_decomposer.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

#include "mnemonics.h"  // NOLINT

namespace instrument {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicBlockDecomposer;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicCodeBlock;
using block_graph::BlockGraph;
using block_graph::Instruction;

class TestSecurityCookieCheckHookTransform : public SecurityCookieCheckHookTransform {

};

class SecurityCookieCheckHookTransformTest : public testing::TestDllTransformTest {
protected:
  void CheckBasicBlockInstrumentation();

  TestSecurityCookieCheckHookTransform security_cookie_check_hook_;
};

void SecurityCookieCheckHookTransformTest::CheckBasicBlockInstrumentation() {
  bool hit = false;

  // Let's examine each eligible block to verify that its basic blocks have been
  // instrumented.
  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip everything but __afl_report_gsfailure.
    if (block.name() != "__afl_report_gsfailure")
      continue;

    hit = true;

    // Decompose the block to basic-blocks.
    BasicBlockSubGraph subgraph;
    BasicBlockDecomposer bb_decomposer(&block, &subgraph);
    ASSERT_TRUE(bb_decomposer.Decompose());

    // Retrieve the first basic block.
    ASSERT_EQ(1, subgraph.block_descriptions().size());
    const BasicBlockSubGraph::BasicBlockOrdering& original_order =
        subgraph.block_descriptions().front().basic_block_order;
    BasicCodeBlock* first_bb = BasicCodeBlock::Cast(*original_order.begin());
    ASSERT_NE(first_bb, nullptr);

    // Check if each non-padding basic code-block begins with the
    // instrumentation sequence.
    BasicBlockSubGraph::BBCollection::const_iterator bb_iter =
        subgraph.basic_blocks().begin();
    for (; bb_iter != subgraph.basic_blocks().end(); ++bb_iter) {
      const BasicCodeBlock* bb = BasicCodeBlock::Cast(*bb_iter);
      if (bb == nullptr || bb->is_padding())
        continue;

      BasicBlock::Instructions::const_iterator inst_iter = bb->instructions().begin(),
                                               end_iter = bb->instructions().end();
      ASSERT_NE(inst_iter, end_iter);
      // mov [deadbeef], eax
      const Instruction& inst = *inst_iter;
      EXPECT_EQ(I_MOV, inst.representation().opcode);
    }
  }

  EXPECT_TRUE(hit);
}

}  // namespace

TEST_F(SecurityCookieCheckHookTransformTest, ApplyTranform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
    &security_cookie_check_hook_, policy_,
    &block_graph_, header_block_
  ));

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation());
}

}  // namespace transforms
}  // namespace instrument
