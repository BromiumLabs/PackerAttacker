#pragma once
#include "StackWalker.h"
#include "Logger.h"
#include <functional>
#include <string>

class DebugStackTracer : public StackWalker
{
public:
  DebugStackTracer() : StackWalker() {}

  DebugStackTracer(std::function<void(std::string)> callback) : StackWalker(StackWalker::RetrieveNone, NULL, GetCurrentProcessId(), GetCurrentProcess())
  {
      this->lineCallback = callback;
  }

protected:
	virtual void OnOutput(LPCSTR szText)
	{
        lineCallback(std::string(szText));
    }

private:
	std::function<void(std::string)> lineCallback;
};