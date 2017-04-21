// Axel '0vercl0k' Souchet 20 April 2017
#include "syzygy/instrument/transforms/add_implicit_tls_transform.h"

#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/unittest_util.h"


namespace instrument {
namespace transforms {

typedef block_graph::BlockGraph BlockGraph;

namespace {

class TestAddImplicitTlsTransform : public AddImplicitTlsTransform {
public:
  TestAddImplicitTlsTransform(BlockGraph::Block *block, size_t offset)
  : AddImplicitTlsTransform(block, offset)
  { }

  using AddImplicitTlsTransform::tls_displacement_;
};

class AddImplicitTlsTransformTest : public testing::TestDllTransformTest {

};

}  // namespace

TEST_F(AddImplicitTlsTransformTest, ApplyTlsInsertionTranform) {
  struct cov {
    uint8_t padd[10];
    uint32_t unused;
    uint32_t here;
    uint32_t nothere;
  };

  BlockGraph::Block *block = block_graph_.AddBlock(
    BlockGraph::DATA_BLOCK,
    sizeof(cov),
    "cov"
  );

  TestAddImplicitTlsTransform add_implicit_tls(
    block, offsetof(cov, here)
  );

  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
    &add_implicit_tls, policy_,
    &block_graph_, header_block_
  ));

  // The tls section is already pretty full, hence the big offset below
  EXPECT_EQ(add_implicit_tls.tls_displacement_, 792);

  // One should be __tls_used (that is the block containing _tls_index),
  // and the other one because the block has been added to the block_graph_
  EXPECT_EQ(2, block->referrers().size());
  const auto &referrers = block->referrers();
  uint8_t count = 0;
  BlockGraph::Block *_tls_used = nullptr;
  for (const auto &referrer : referrers) {
    if (referrer.first->name() == "_tls_used") {
      _tls_used = referrer.first;
      count += 1;
    }

    if (referrer.first->name() == "DllMain") {
      count += 1;
    }

    if (count == 2) {
      break;
    }
  }

  ASSERT_EQ(count, 2);
  ASSERT_NE(_tls_used, nullptr);

  // We get a reference to __tls_index to check in which block, at what offset it's pointing to
  BlockGraph::Reference __tls_index_ref;
  ASSERT_TRUE(
    _tls_used->GetReference(
      offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex),
      &__tls_index_ref
    )
  );

  // We make sure _tls_index does point in our block, at the offset we wanted
  BlockGraph::Block *__tls_index = __tls_index_ref.referenced();
  ASSERT_EQ(__tls_index, block);
  ASSERT_EQ(__tls_index_ref.offset(), offsetof(cov, here));
}

}  // namespace transforms
}  // namespace instrument
