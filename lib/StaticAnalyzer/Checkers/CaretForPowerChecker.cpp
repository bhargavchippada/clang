//== CaretForPowerChecker.cpp - Correct usage of ^ checker ----------------
// C++---==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-----------------------------------------------------------------------------===//
//
// This defines CaretForPowerChecker, a builtin check in ExprEngine that
// performs checks for usage of ^ by beginners who think it computes power
// instead of xor.
//
// Author: Bhargav Chippada
//===-----------------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class CaretForPowerChecker : public Checker<check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BuiltinBug> BT;
  void reportBug(const char *Msg, CheckerContext &C) const;

 public:
  CaretForPowerChecker();
  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
};
}  // end anonymous namespace

CaretForPowerChecker::CaretForPowerChecker() {
  // Initialize the bug types.
  BT.reset(new BuiltinBug(this, "^ is xor operator, not power"));
}

void CaretForPowerChecker::reportBug(const char *Msg, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N) return;

  auto R = llvm::make_unique<BugReport>(*BT, Msg, N);
  C.emitReport(std::move(R));
}

void CaretForPowerChecker::checkPreStmt(const BinaryOperator *B,
                                        CheckerContext &C) const {
  BinaryOperator::Opcode Op = B->getOpcode();
  if (Op != BO_Xor && Op != BO_XorAssign) return;

  reportBug("^ is xor operator, not power", C);
}

void ento::registerCaretForPowerChecker(CheckerManager &mgr) {
  mgr.registerChecker<CaretForPowerChecker>();
}