// Axel '0vercl0k' Souchet 5 Feb 2017
#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_AFL_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_AFL_TRANSFORM_H_

#include "base/logging.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/basic_block_assembler.h"

#include <random>
#include <algorithm>

namespace instrument {
namespace transforms {

typedef block_graph::BlockGraph BlockGraph;
typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
typedef block_graph::BasicCodeBlock BasicCodeBlock;
typedef block_graph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockAssembler BasicBlockAssembler;
typedef block_graph::BlockBuilder BlockBuilder;

typedef core::RelativeAddress RelativeAddress;
typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;

class AFLTransform :
  // We need an IterativeTransform for iterating through the Blocks
  public block_graph::transforms::IterativeTransformImpl<AFLTransform>,
  //..And iterating over basic blocks
  public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<AFLTransform>
  {

public:
  AFLTransform(
    const std::unordered_set<std::string> &targets,
    bool whitelist_mode,
    bool force_decompose,
    bool multithread,
    bool cookie_check_hook
  )
  : tls_afl_prev_loc_displacement_(0),
    whitelist_mode_(whitelist_mode),
    force_decompose_(force_decompose), multithread_(multithread),
    cookie_check_hook_(cookie_check_hook),
    total_blocks_(0), total_code_blocks_(0), total_code_blocks_instrumented_(0)
  {
    for(const auto &target : targets) {
      targets_visited_.emplace(target, false);
    }
  }

  static const char kTransformName[];

  // Functions needed for IterativTransform
  bool PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block
  );

  bool OnBlock(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* block
  );

  bool PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block
  );

  // Needed for NamedBasicBlockSubGraphTransformImpl
  bool TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph
  ) final;

  const RelativeAddressRangeVector& bb_ranges() {
    return bb_ranges_;
  }

protected:
  // Basic-block instrumentation related functions
  bool ShouldInstrumentBlock(
    BlockGraph::Block* block
  );
  void EmitAFLInstrumentation(
    BasicCodeBlock &bcb,
    BlockGraph* block_graph
  );
  void instrument(
    block_graph::BasicBlockAssembler &assm,
    unsigned int cur_loc
  );

  // The data-block that keeps the metadata regarding the instrumentation
  BlockGraph::Block *afl_static_cov_data_;

  // This is the offset from the TLS memory where the __afl_prev_loc slot has been placed
  size_t tls_afl_prev_loc_displacement_;

  // Stores the RVAs in the original image for each instrumented basic block.
  RelativeAddressRangeVector bb_ranges_;

  // Various configuration switches coming from the command line
  std::map<std::string, bool> targets_visited_;
  bool whitelist_mode_;
  bool force_decompose_;
  bool multithread_;
  bool cookie_check_hook_;

  // Stats
  size_t total_blocks_;
  size_t total_code_blocks_;
  size_t total_code_blocks_instrumented_;
};

class RandomCtr {
public:
  RandomCtr(const size_t b)
  : idx_(0) {
    for (size_t i = 0; i < b; ++i) {
      numbers_.push_back(i);
    }

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(numbers_.begin(), numbers_.end(), g);
  }

  size_t next() {
    return numbers_[idx_++ % numbers_.size()];
  }

private:
  std::vector<size_t> numbers_;
  size_t idx_;
};

} // instrument
} // transforms

#endif
