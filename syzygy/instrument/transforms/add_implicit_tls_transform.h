// Axel '0vercl0k' Souchet 1 April 2017
#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ADD_IMPLICIT_TLS_TRANSFORM_H
#define SYZYGY_INSTRUMENT_TRANSFORMS_ADD_IMPLICIT_TLS_TRANSFORM_H

#include "base/logging.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/block_graph/transform_policy.h"

namespace instrument {
namespace transforms {

typedef block_graph::BlockGraph BlockGraph;
typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

class AddImplicitTlsTransform :
public block_graph::transforms::NamedBlockGraphTransformImpl<
          AddImplicitTlsTransform> {

public:
  AddImplicitTlsTransform(BlockGraph::Block *afl_static_cov_data, size_t tls_index_offset)
  : afl_static_cov_data_(afl_static_cov_data), tls_index_offset_(tls_index_offset)
  {  }

  static const char kTransformName[];

  bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                 BlockGraph* block_graph,
                                 BlockGraph::Block* header_block) final;

  const size_t tls_displacement() {
    return tls_displacement_;
  }

protected:
  bool CreateImplicitTlsSlot(BlockGraph* block_graph, BlockGraph::Block* header_block);
  bool InsertImplicitTlsSlot(BlockGraph* block_graph);

  // This is the data-block we will redirect TlsIndex in
  BlockGraph::Block *afl_static_cov_data_;
  // This is the offset (relative to the above data block) at which
  // TlsIndex is placed
  size_t tls_index_offset_;
  // This is the displacement offset of where the TLS variable is placed at in the memory
  // allocated by the loader to back the slots:
  // variable address is at (TEB.ThreadLocalStoragePointer[TlsIndex] + tls_displacement_)
  size_t tls_displacement_;
};

}
}

#endif
