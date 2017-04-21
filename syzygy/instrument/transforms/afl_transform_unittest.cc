// Axel '0vercl0k' Souchet 18 April 2017
#include "syzygy/instrument/transforms/afl_transform.h"

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

class TestAFLTransform : public AFLTransform {
public:
  TestAFLTransform(
    const std::unordered_set<std::string> &targets,
    bool whitelist_mode,
    bool force_decompose,
    bool multithread,
    bool cookie_check_hook
  )
  : AFLTransform(
    targets, whitelist_mode,
    force_decompose, multithread,
    cookie_check_hook
  )
  { }

  using AFLTransform::multithread_;
  using AFLTransform::total_code_blocks_instrumented_;
  using AFLTransform::total_code_blocks_;
  using AFLTransform::targets_visited_;
  using AFLTransform::whitelist_mode_;
};

class AFLTransformTest : public testing::TestDllTransformTest {
protected:
  void CheckBasicBlockInstrumentation(TestAFLTransform &afl);
  void CheckInstrumentation(
    BasicBlock::Instructions::const_iterator &iter,
    const BasicBlock::Instructions::const_iterator &end,
    bool multithread
  );
};

void AFLTransformTest::CheckInstrumentation(
  BasicBlock::Instructions::const_iterator &iter,
  const BasicBlock::Instructions::const_iterator &end,
  bool multithread
) {
  // push eax
  const Instruction& inst1 = *iter;
  EXPECT_EQ(I_PUSH, inst1.representation().opcode);
  ASSERT_NE(++iter, end);

  // push ebx
  const Instruction& inst2 = *iter;
  EXPECT_EQ(I_PUSH, inst2.representation().opcode);
  ASSERT_NE(++iter, end);

  if (multithread) {
    // push ecx
    const Instruction& inst3 = *iter;
    EXPECT_EQ(I_PUSH, inst3.representation().opcode);
    ASSERT_NE(++iter, end);
  }

  // lahf
  const Instruction& inst4 = *iter;
  EXPECT_EQ(I_LAHF, inst4.representation().opcode);
  ASSERT_NE(++iter, end);

  // seto al
  const Instruction& inst5 = *iter;
  EXPECT_EQ(I_SETO, inst5.representation().opcode);
  ASSERT_NE(++iter, end);

  if (multithread) {
    // mov ecx, tls_index
    const Instruction& inst6 = *iter;
    EXPECT_EQ(I_MOV, inst6.representation().opcode);
    EXPECT_EQ(1, inst6.references().size());
    ASSERT_NE(++iter, end);

    // mov ebx, fs:[2C]
    const Instruction& inst7 = *iter;
    EXPECT_EQ(I_MOV, inst7.representation().opcode);
    ASSERT_NE(++iter, end);

    // mov ecx, [ebx + ecx * 4]
    const Instruction& inst8 = *iter;
    EXPECT_EQ(I_MOV, inst8.representation().opcode);
    ASSERT_NE(++iter, end);

    // lea ecx, [ecx + offset]
    const Instruction& inst9 = *iter;
    EXPECT_EQ(I_LEA, inst9.representation().opcode);
    ASSERT_NE(++iter, end);
  }

  // mov ebx, ID
  const Instruction& inst10 = *iter;
  EXPECT_EQ(I_MOV, inst10.representation().opcode);
  ASSERT_NE(++iter, end);

  if (multithread) {
    // xor ebx, [ecx]
    const Instruction& inst11 = *iter;
    EXPECT_EQ(I_XOR, inst11.representation().opcode);
    ASSERT_NE(++iter, end);
  } else {
    // xor ebx, [afl_prev_loc]
    const Instruction& inst12 = *iter;
    EXPECT_EQ(I_XOR, inst12.representation().opcode);
    EXPECT_EQ(1, inst12.references().size());
    ASSERT_NE(++iter, end);
  }

  // add ebx, [afl_area_ptr]
  const Instruction& inst13 = *iter;
  EXPECT_EQ(I_ADD, inst13.representation().opcode);
  EXPECT_EQ(1, inst13.references().size());
  ASSERT_NE(++iter, end);

  // inc byte [ebx]
  const Instruction& inst14 = *iter;
  EXPECT_EQ(I_INC, inst14.representation().opcode);
  ASSERT_NE(++iter, end);

  if (multithread) {
    // mov [ecx], id >> 1
    const Instruction& inst15 = *iter;
    EXPECT_EQ(I_MOV, inst15.representation().opcode);
    ASSERT_NE(++iter, end);
  } else {
    // mov [afl_prev_loc], id >> 1
    const Instruction& inst16 = *iter;
    EXPECT_EQ(I_MOV, inst16.representation().opcode);
    EXPECT_EQ(1, inst16.references().size());
    ASSERT_NE(++iter, end);
  }

  // add al, 0x7F
  const Instruction& inst17 = *iter;
  EXPECT_EQ(I_ADD, inst17.representation().opcode);
  ASSERT_NE(++iter, end);

  // sahf
  const Instruction& inst18 = *iter;
  EXPECT_EQ(I_SAHF, inst18.representation().opcode);
  ASSERT_NE(++iter, end);

  if (multithread) {
    // pop ecx
    const Instruction& inst19 = *iter;
    EXPECT_EQ(I_POP, inst19.representation().opcode);
    ASSERT_NE(++iter, end);
  }

  // pop ebx
  const Instruction& inst20 = *iter;
  EXPECT_EQ(I_POP, inst20.representation().opcode);
  ASSERT_NE(++iter, end);

  // pop eax
  const Instruction& inst21 = *iter;
  EXPECT_EQ(I_POP, inst21.representation().opcode);
}

void AFLTransformTest::CheckBasicBlockInstrumentation(TestAFLTransform &afl) {
  bool multithread = afl.multithread_;

  // Let's examine each eligible block to verify that its basic blocks have been
  // instrumented.
  BlockGraph::BlockMap::const_iterator block_iter =
      block_graph_.blocks().begin();
  for (; block_iter != block_graph_.blocks().end(); ++block_iter) {
    const BlockGraph::Block& block = block_iter->second;

    // Skip non-code blocks.
    if (block.type() != BlockGraph::CODE_BLOCK)
      continue;

    // Skip non-decomposable blocks.
    if (!policy_->BlockIsSafeToBasicBlockDecompose(&block))
      continue;

    if (afl.targets_visited_.size() != 0) {
      bool hit = false;
      for (const auto &target : afl.targets_visited_) {
        if (block.name() == target.first) {
          hit = true;
          break;
        }
      }

      // In whitelist mode, if we don't have a hit we skip the block
      // In blacklist mode, if we have a hit we skip the block
      if ((afl.whitelist_mode_ && !hit) || (!afl.whitelist_mode_ && hit)) {
        continue;
      }
    }

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
      CheckInstrumentation(inst_iter, end_iter, multithread);
    }
  }
}

}  // namespace

TEST_F(AFLTransformTest, ApplyTranform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl(
    { },   // targets
    false, // whitelist_mode
    false, // force_decompose
    false, // multithread
    false  // cookie_check_hook
  );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl, policy_, &block_graph_, header_block_));

  size_t instrumentation_percentage = (
    afl.total_code_blocks_instrumented_ * 100
  ) / afl.total_code_blocks_;

  EXPECT_GT(instrumentation_percentage, 70);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl));
}

TEST_F(AFLTransformTest, ApplyTranformMultithread) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl_mt(
    { },   // targets
    false, // whitelist_mode
    false, // force_decompose
    true,  // multithread
    false  // cookie_check_hook
  );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl_mt, policy_, &block_graph_, header_block_));

  size_t instrumentation_percentage = (
    afl_mt.total_code_blocks_instrumented_ * 100
  ) / afl_mt.total_code_blocks_;

  EXPECT_GT(instrumentation_percentage, 70);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl_mt));
}

TEST_F(AFLTransformTest, ApplyTranformWhitelist) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl_whitelist(
    { "fuzzme", "pattern1", "_pattern2", "Unused::M" }, // targets
    true,                                               // whitelist_mode
    false,                                              // force_decompose
    false,                                              // multithread
    false                                               // cookie_check_hook
  );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl_whitelist, policy_, &block_graph_, header_block_));

  EXPECT_EQ(afl_whitelist.total_code_blocks_instrumented_, 1);

  EXPECT_FALSE(afl_whitelist.targets_visited_["fuzzme"]);
  EXPECT_FALSE(afl_whitelist.targets_visited_["pattern1"]);
  EXPECT_FALSE(afl_whitelist.targets_visited_["_pattern2"]);
  EXPECT_TRUE(afl_whitelist.targets_visited_["Unused::M"]);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl_whitelist));
}

TEST_F(AFLTransformTest, ApplyTranformBlacklist) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  TestAFLTransform afl_blacklist(
    { "fuzzme", "pattern1", "_pattern2", "Unused::M" }, // targets
    false,                                              // whitelist_mode
    false,                                              // force_decompose
    false,                                              // multithread
    false                                               // cookie_check_hook
  );

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &afl_blacklist, policy_, &block_graph_, header_block_));

  size_t instrumentation_percentage = (
    afl_blacklist.total_code_blocks_instrumented_ * 100
  ) / afl_blacklist.total_code_blocks_;

  EXPECT_GT(instrumentation_percentage, 70);

  EXPECT_FALSE(afl_blacklist.targets_visited_["fuzzme"]);
  EXPECT_FALSE(afl_blacklist.targets_visited_["pattern1"]);
  EXPECT_FALSE(afl_blacklist.targets_visited_["_pattern2"]);
  EXPECT_TRUE(afl_blacklist.targets_visited_["Unused::M"]);

  ASSERT_NO_FATAL_FAILURE(CheckBasicBlockInstrumentation(afl_blacklist));
}

}  // namespace transforms
}  // namespace instrument
