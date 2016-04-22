//===-- WarnFunctionsUseChecker.cpp -------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Defines a checker that checks for the usage of certain predefined functions
//
// Author: Bhargav Chippada
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <cstdlib>
#include <string>
#include <vector>

#include "configuration.h"
#include <fstream>

using namespace clang;
using namespace ento;

namespace {
class WarnFunctionsUseChecker : public Checker<check::PreCall> {
  std::unique_ptr<BuiltinBug> BT;
  std::vector<char *> warnFunctions;

  void reportBug(const char *Msg, CheckerContext &C) const;

 public:
  WarnFunctionsUseChecker();
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
}  // end anonymous namespace

WarnFunctionsUseChecker::WarnFunctionsUseChecker() {
  // Get config file location
  char *env_p = std::getenv("PRUTOR_CONFIG_LOC");

  configuration::data myconfigdata;
  std::ifstream f(env_p);
  if (f != NULL) {
    f >> myconfigdata;
    f.close();

    // Retrieve what functions to be warned
    std::string str = myconfigdata["PRUTOR_WARN_FUNCS"];
    char *funcs = new char[str.size() + 1];
    std::copy(str.begin(), str.end(), funcs);
    funcs[str.size()] = '\0';
    char *func = strtok(funcs, " ;,-");
    while (func) {
      warnFunctions.push_back(func);
      func = strtok(NULL, " ;,-");
    }
  }

  // Initialize the bug types.
  BT.reset(new BuiltinBug(this, "Warn usage of particular builtin functions"));
}

void WarnFunctionsUseChecker::reportBug(const char *Msg,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N) return;

  auto R = llvm::make_unique<BugReport>(*BT, Msg, N);
  C.emitReport(std::move(R));
}

void WarnFunctionsUseChecker::checkPreCall(const CallEvent &Call,
                                           CheckerContext &C) const {
  /*If the callee function is not in the system headers then return because it
   * means the function being used is not a builtin function
  */
  if (!Call.isInSystemHeader()) return;

  // Finding desired builtin function call
  for (unsigned int i = 0; i < warnFunctions.size(); i++) {
    if (Call.isGlobalCFunction(warnFunctions[i])) {
      std::string msg(warnFunctions[i]);
      msg = "Do not use '" + msg + "' builtin function, declare it yourself";
      reportBug(msg.c_str(), C);
      return;
    }
  }
  return;
}

void ento::registerWarnFunctionsUseChecker(CheckerManager &mgr) {
  mgr.registerChecker<WarnFunctionsUseChecker>();
}