//== IntByIntDivChecker.cpp - Int by Int Division checker --------------*- C++
//-*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-----------------------------------------------------------------------------===//
//
// This defines IntByIntDivChecker, a builtin check in ExprEngine that performs
// checks for Int by Int divisions.
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
class IntByIntDivChecker : public Checker<check::PreStmt<BinaryOperator> > {
  mutable std::unique_ptr<BuiltinBug> BT;
  void reportBug(const char *Msg, CheckerContext &C) const;

 public:
  IntByIntDivChecker();
  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
};
}  // end anonymous namespace

IntByIntDivChecker::IntByIntDivChecker() {
  // Initialize the bug types.
  BT.reset(new BuiltinBug(this, "Int By Int Division"));
}

void IntByIntDivChecker::reportBug(const char *Msg, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N) return;

  auto R = llvm::make_unique<BugReport>(*BT, Msg, N);
  C.emitReport(std::move(R));
}

static bool isIntType(QualType Ty) {
  if (Ty->isIntegerType())  // C++ or C99
    return true;

  return false;
}

void IntByIntDivChecker::checkPreStmt(const BinaryOperator *B,
                                      CheckerContext &C) const {
  BinaryOperator::Opcode Op = B->getOpcode();
  if (Op != BO_Div && Op != BO_DivAssign) return;

  QualType LHSType = B->getLHS()->getType();
  QualType RHSType = B->getRHS()->getType();

  if (!isIntType(LHSType) || !isIntType(RHSType)) return;

  reportBug("Int By Int Division", C);
}

void ento::registerIntByIntDivChecker(CheckerManager &mgr) {
  mgr.registerChecker<IntByIntDivChecker>();
}