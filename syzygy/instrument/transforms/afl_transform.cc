// Axel '0vercl0k' Souchet 5Feb2017
#include "syzygy/instrument/transforms/afl_transform.h"

#include "syzygy/pe/pe_utils.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/instrument/transforms/security_cookie_check_hook_transform.h"
#include "syzygy/instrument/transforms/add_implicit_tls_transform.h"

namespace instrument {
namespace transforms {

using block_graph::TypedBlock;
using block_graph::Displacement;
using block_graph::Operand;
using block_graph::Immediate;

const char AFLTransform::kTransformName[] = "AFLTransform";

/* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
2; you probably want to keep it under 18 or so for performance reasons
(adjusting AFL_INST_RATIO when compiling is probably a better way to solve
problems with complex programs). You need to recompile the target binary
after changing this - otherwise, SEGVs may ensue. */

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

#pragma pack(push, 1)
// Describe the layout of the .afl section
typedef struct {
  UINT32 __tls_index;       // This is not used in SingleThread mode. It'll still be added in the binary though
  UINT32 __tls_slot_offset; // This is 0 if __tls_index isn't in use
  PUINT32 __afl_prev_loc;
  PUCHAR __afl_area_ptr;
  CHAR __afl_area[MAP_SIZE];
} STATIC_COVERAGE_DATA, *PSTATIC_COVERAGE_DATA;

// Describe the layout of the .tls section when using the MultiThread mode
typedef struct {
  uint32_t __tls_start;
  uint32_t __afl_prev_loc_tls;
  uint8_t __tls_end;
} DOT_TLS_SECTION_CONTENT;
#pragma pack(pop)

static RandomCtr random_ctr(MAP_SIZE);

bool AFLTransform::PreBlockGraphIteration(
  const TransformPolicyInterface* policy,
  BlockGraph* block_graph,
  BlockGraph::Block* header_block
) {
  // Creates a r/w section where we'll stuff the metadatas
  BlockGraph::Section* section = block_graph->FindOrAddSection(
    ".afl",
    pe::kReadWriteDataCharacteristics
  );

  if (section == NULL) {
    LOG(ERROR) << "Failed to find/add read-write data section";
    return false;
  }

  afl_static_cov_data_ = block_graph->AddBlock(
    BlockGraph::DATA_BLOCK,
    sizeof(STATIC_COVERAGE_DATA),
    "__afl_static_cov_data"
  );

  if (afl_static_cov_data_ == NULL) {
    LOG(ERROR) << "Failed to add the afl_static_cov_data_ block.";
    return false;
  }

  afl_static_cov_data_->set_section(section->id());
  PSTATIC_COVERAGE_DATA static_cov_data = PSTATIC_COVERAGE_DATA(
    afl_static_cov_data_->AllocateData(
      // Trick here is to only ask for 'file' backing for the first part of the structure
      // because we actually need their values initialized.
      // As opposed to the huge __afl_area array that we only care when the PE is loaded in memory.
      // So the idea is to have a small section on disk, but a bigger one in memory.
      // This avoids to waste file space that we do not need
      // (aligned on the FileAlignement).
      offsetof(STATIC_COVERAGE_DATA, __afl_area)
    )
  );

  // Initialize afl_area_ptr with a pointer to the coverage bitmap embedded in the binary.
  // This ensures the target can run without runtime patching by WinAFL
  afl_static_cov_data_->SetReference(
    offsetof(STATIC_COVERAGE_DATA, __afl_area_ptr),
    BlockGraph::Reference(
      BlockGraph::ABSOLUTE_REF,
      BlockGraph::Reference::kMaximumSize,
      afl_static_cov_data_,
      offsetof(STATIC_COVERAGE_DATA, __afl_area),
      0
    )
  );

  // Hook __security_cookie_check if needed
  if (cookie_check_hook_) {
    SecurityCookieCheckHookTransform cookie_hook;
    if (!ApplyBlockGraphTransform(&cookie_hook, policy, block_graph, header_block)) {
      LOG(ERROR) << "The SecurityCookieCheckHookTransform transform failed.";
    }
  }

  if (multithread_) {
    // afl_static_cov_data_ is needed in order for the transform to redirect the TlsIndex
    // directly inside the .afl section to have it available in the AFL meta-data (it will be
    // consumed by the harness and the persistent loop implementation).
    // It also needs to know at what offset (relative to afl_static_cov_data_) TlsIndex is
    AddImplicitTlsTransform afl_prev_loc_tls(
      afl_static_cov_data_, offsetof(STATIC_COVERAGE_DATA, __tls_index)
    );

    if (!ApplyBlockGraphTransform(&afl_prev_loc_tls, policy, block_graph, header_block)) {
      LOG(ERROR) << "The AddImplicitTlsTransform transform failed.";
      return false;
    }

    // We need the displacement in order to be able to generate the proper instrumentation
    tls_afl_prev_loc_displacement_ = afl_prev_loc_tls.tls_displacement();
  }

  // Keep track of the implicit TLS slot offset, inside the .afl section.
  // This will get consumed by the __afl_persistent_loop() in the target harness
  static_cov_data->__tls_slot_offset = tls_afl_prev_loc_displacement_;
  if(tls_afl_prev_loc_displacement_ != 0) {
    LOG(INFO) << "Placing TLS slot at offset +" << tls_afl_prev_loc_displacement_ << ".";
  }

  return true;
}

bool AFLTransform::ShouldInstrumentBlock(
  BlockGraph::Block* block
) {
  bool should_instrument = true;
  std::string name(block->name());

  // We are ignoring every functions prefixed by __afl (the set-up, persitent_loop, veh functions)
  if (!name.compare(0, 5, "__afl")) {
    return false;
  }

  // Check if we are in whitelist/blacklist mode
  if (targets_visited_.size() != 0) {
    bool found_match = false;
    for (auto &target : targets_visited_) {
      found_match = name.find(target.first) != std::string::npos;
      if (found_match) {
        target.second = true;
        break;
      }
    }

    // If we are on blacklist mode: if we find a match it means that
    // this is a block we do not want to instrument
    if (found_match && !whitelist_mode_) {
      should_instrument = false;
    }

    // If we are on whitelist: Not finding a match means we shouldn't
    // instrument this block
    if (!found_match && whitelist_mode_) {
      should_instrument = false;
    }
  }

  if (should_instrument && name != "") {
    VLOG(1) << "Instrumenting " << name;
  }

  return should_instrument;
}

bool AFLTransform::OnBlock(
  const TransformPolicyInterface* policy,
  BlockGraph* block_graph,
  BlockGraph::Block* block
) {

  total_blocks_++;

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  total_code_blocks_++;

  // Use the policy to skip blocks that aren't eligible for basic block
  // decomposition. Let the user be able to override it though
  if (force_decompose_ == false) {
    if (!policy->BlockIsSafeToBasicBlockDecompose(block)) {
      VLOG(1) << "Not instrumenting " << block->name();
      return true;
    }
  }

  if (!ShouldInstrumentBlock(block))
    return true;

  total_code_blocks_instrumented_++;

  if (!ApplyBasicBlockSubGraphTransform(this, policy, block_graph, block, NULL)) {
    LOG(ERROR) << "ApplyBasicBlockSubGraphTransform failed, but ignoring.";
    return true;
  }

  return true;
}

bool AFLTransform::PostBlockGraphIteration(
  const TransformPolicyInterface* policy,
  BlockGraph* block_graph,
  BlockGraph::Block* header_block
) {
  LOG(INFO) << "            Number of Blocks found: " << total_blocks_;
  LOG(INFO) << "       Number of code Blocks found: " << total_code_blocks_;
  LOG(INFO) << "Number of code Blocks instrumented: " << total_code_blocks_instrumented_;
  LOG(INFO) << "     Percentage of instrumentation: " << (total_code_blocks_instrumented_ * 100) / total_code_blocks_ << "%";
  return true;
}

void AFLTransform::instrument(
  block_graph::BasicBlockAssembler &assm,
  unsigned int cur_loc
) {
  BasicBlockAssembler::Operand afl_prev_loc(
    Displacement(
      afl_static_cov_data_,
      offsetof(STATIC_COVERAGE_DATA, __afl_prev_loc)
    )
  ), afl_area_ptr(
    Displacement(
      afl_static_cov_data_,
      offsetof(STATIC_COVERAGE_DATA, __afl_area_ptr)
    )
  ), tls_index(
    Displacement(
      afl_static_cov_data_,
      offsetof(STATIC_COVERAGE_DATA, __tls_index)
    )
  );

  // Saves state
  assm.push(assm::eax);
  assm.push(assm::ebx);

  if (multithread_) {
    assm.push(assm::ecx);
  }

  assm.lahf();
  assm.set(assm::kOverflow, assm::eax);

  if (multithread_) {
    // Get __afl_prev_loc from TLS
    // mov ecx, tls_index
    assm.mov(assm::ecx, tls_index);
    // mov ebx, fs:[2C] <- encoding is smaller with @eax as dest
    assm.mov_fs(assm::ebx, Immediate(0x2C)); // offsetof(TEB, ThreadLocalStoragePointer)
    // mov ecx, [ebx + ecx * 4]
    assm.mov(assm::ecx, Operand(assm::ebx, assm::ecx, assm::kTimes4));
    // lea ecx, [ecx + offset]
    assm.lea(assm::ecx, Operand(assm::ecx, Displacement(tls_afl_prev_loc_displacement_)));
  }

  // mov ebx, ID
  assm.mov(assm::ebx, Immediate(cur_loc, assm::kSize32Bit));

  if (multithread_) {
    // xor ebx, [ecx]
    assm.xor(assm::ebx, Operand(assm::ecx));
  } else {
    // xor ebx, [afl_prev_loc]
    assm.xor(assm::ebx, afl_prev_loc);
  }

  // add ebx, [afl_area_ptr]
  assm.add(assm::ebx, afl_area_ptr);
  // inc byte [ebx]
  assm.inc(Operand(assm::ebx));

  if (multithread_) {
    // mov [ecx], id >> 1
    assm.mov(Operand(assm::ecx), Immediate(cur_loc >> 1, assm::kSize32Bit));
  } else {
    // mov [afl_prev_loc], id >> 1
    assm.mov(afl_prev_loc, Immediate(cur_loc >> 1, assm::kSize32Bit));
  }

  // Restores OF if set by making the add overflow
  assm.add(assm::al, Immediate(0x7F, assm::kSize8Bit));
  // Restores flags
  assm.sahf();

  if (multithread_) {
    assm.pop(assm::ecx);
  }

  assm.pop(assm::ebx);
  assm.pop(assm::eax);
}

void AFLTransform::EmitAFLInstrumentation(
  BasicCodeBlock &bcb,
  BlockGraph* block_graph
) {
  BasicBlock::Instructions& instructions = bcb.instructions();
  block_graph::BasicBlockAssembler assm(
    instructions.begin(), &instructions
  );

  unsigned int cur_loc = random_ctr.next();
  instrument(assm, cur_loc);
}

bool AFLTransform::TransformBasicBlockSubGraph(
  const TransformPolicyInterface* policy,
  BlockGraph* block_graph,
  BasicBlockSubGraph* basic_block_subgraph
) {
  // Iterate through every basic-block and instrument them
  BasicBlockSubGraph::BBCollection& basic_blocks =
    basic_block_subgraph->basic_blocks();

  for (auto &bb : basic_blocks) {
    BasicCodeBlock* bc_block = BasicCodeBlock::Cast(bb);
    if (bc_block == nullptr)
      continue;

    EmitAFLInstrumentation(*bc_block, block_graph);

    BlockGraph::Block::SourceRange source_range;
    if (!GetBasicBlockSourceRange(*bc_block, &source_range)) {
      LOG(ERROR) << "Unable to get source range for basic block '"
                 << bc_block->name() << "'";
      return false;
    }

    bb_ranges_.push_back(source_range);
  }
  return true;
}

} // instrument
} // transforms
