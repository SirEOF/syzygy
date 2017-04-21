// Axel '0vercl0k' Souchet 1 April 2017
#include "syzygy/instrument/transforms/security_cookie_check_hook_transform.h"

#include "syzygy/pe/pe_utils.h"
#include "syzygy/block_graph/typed_block.h"

namespace instrument {
namespace transforms {

using block_graph::TypedBlock;
using block_graph::Displacement;
using block_graph::Operand;
using block_graph::Immediate;

const char SecurityCookieCheckHookTransform::kTransformName[] = "SecurityCookieCheckHookTransform";

// Why doesn't this transform hook __security_check_cookie?
//  Because it is compiled as valid indirect call target when CFG is used (because called indirectly
//  by exception handlers). This means when we transfer the referrers of the function to our code block,
//  this can break the ordering of RVAs in the LoadConfig.GuardCFFunctionTable table.

// Why does transfering referrers (from __security_check_cookie to __afl_security_check_cookie)
// is not a good idea?
//  First, a bit of context
//   Microsoft introduced a control-flow integrity solution called CFG - the compiler instruments
//   indirect call to call into a 'check function' before actually calling indirectly the target.
//   The linker generates meta-data informations, like the list of valid indirect call targets. One important
//   property of this list, is that it is expected to be ordered from the lowest RVA to the highest.
//   [0xABC, 0xABD, 0xBA0] is a valid table, but [0xABC, 0xBA0, 0xABD] is not. Let's assume __security_cookie_check has the RVA 0xABD
//  The issue
//   When syzygy goes and transfer the referrers to __security_check_cookie - that lives at 0xBA1 let's say - it also updates the CFG
//   list (LoadConfigDirectory.GuardCFFunctionTable) which means now we have:
//   [0xABC, 0xBA1, 0xBA0] which is not a valid list. The kernel returns a STATUS_INVALID_IMAGE_FORMAT/c000007b error code in that case,
//   when nt!NtCreateSection the image.
//  The solution
//   We hook __report_gs_failure instead which isn't referenced indirectly, thus not inside the GuardCFFunctionTable
//   table.

bool SecurityCookieCheckHookTransform::TransformBlockGraph(
  const TransformPolicyInterface* policy,
  BlockGraph* block_graph,
  BlockGraph::Block* header_block
) {
  BlockGraph::Block *__report_gsfailure = nullptr;
  const BlockGraph::BlockMap &blocks = block_graph->blocks();
  for (const auto &block : blocks) {
    std::string name(block.second.name());
    if (name == "__report_gsfailure") {
      __report_gsfailure = block_graph->GetBlockById(block.first);
      break;
    }
  }

  if (__report_gsfailure == nullptr) {
    LOG(ERROR) << "Could not find __report_gsfailure.";
    return false;
  }

  LOG(INFO) << "Found a __report_gsfailure implementation, hooking it now..";
  BlockGraph::Section* section_text = block_graph->FindOrAddSection(
    pe::kCodeSectionName,
    pe::kCodeCharacteristics
  );

  // All of the below is needed to build the instrumentation via the assembler
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
    "__afl_report_gsfailure",
    nullptr,
    BlockGraph::CODE_BLOCK,
    section_text->id(),
    1,
    0
  );

  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock("__afl_report_gsfailure");
  block_desc->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());
  assm.mov(
    Operand(Displacement(0xdeadbeef)),
    assm::eax
  );

  // Condense into a block
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build __afl_report_gsfailure block.";
    return false;
  }

  // Exactly one new block should have been created
  if (block_builder.new_blocks().size() != 1) {
    LOG(ERROR) << "Exactly one block should have been built by the block_builder.";
    return false;
  }

  if (__report_gsfailure->references().size() != 1) {
    VLOG(1) << "Only a single reference - __security_check_cookie - is expected.";
  }

  // Transfer the referrers to the new block, and delete the old one
  BlockGraph::Block* __afl_report_gsfailure = block_builder.new_blocks().front();
  __report_gsfailure->TransferReferrers(
    0,
    __afl_report_gsfailure,
    BlockGraph::Block::kTransferInternalReferences
  );

  __report_gsfailure->RemoveAllReferences();
  if (!block_graph->RemoveBlock(__report_gsfailure)) {
    LOG(ERROR) << "Removing __report_gsfailure failed.";
    return false;
  }

  return true;
}

}
}
