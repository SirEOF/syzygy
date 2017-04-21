// Axel '0vercl0k' Souchet 1 April 2017
#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_SECURITY_COOKIE_CHECK_HOOK_TRANSFORM_H
#define SYZYGY_INSTRUMENT_TRANSFORMS_SECURITY_COOKIE_CHECK_HOOK_TRANSFORM_H

#include "base/logging.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/basic_block_assembler.h"

namespace instrument {
namespace transforms {

typedef block_graph::BlockGraph BlockGraph;
typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
typedef block_graph::BasicCodeBlock BasicCodeBlock;
typedef block_graph::BasicBlockAssembler BasicBlockAssembler;
typedef block_graph::BlockBuilder BlockBuilder;

class SecurityCookieCheckHookTransform :
public block_graph::transforms::NamedBlockGraphTransformImpl<
          SecurityCookieCheckHookTransform> {

public:
  SecurityCookieCheckHookTransform() {  }

  static const char kTransformName[];

  // BlockGraphTransformInterface Implementation
  bool TransformBlockGraph(const TransformPolicyInterface* policy,
                                 BlockGraph* block_graph,
                                 BlockGraph::Block* header_block) final;

};

}
}

#endif
