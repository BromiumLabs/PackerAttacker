#include "Logger.h"

#include <assert.h>
#include <stdarg.h>
#include <time.h>

Logger* Logger::instance= NULL;

Logger::Logger(void)
{
}
Logger::~Logger(void)
{
}
void Logger::initialize(std::string fileName)
{
    this->logFile = new std::fstream(fileName, std::ios::out);
}
void Logger::uninitialize()
{
    assert(this->logFile);
    this->logFile->close();
    delete this->logFile;
}

void Logger::write(std::string line)
{
    assert(this->logFile);
    //assert(this->logFile->open());

    this->writePrefix();
    this->logFile->write(line.c_str(), line.length());

    if (line[line.length() - 1] != '\n')
        this->logFile->write("\n", 1);

    this->logFile->flush();
}
void Logger::write(const char* format, ...)
{
	char buffer[4096];
    for (int i = 0; i < 4096; i++)
        buffer[i] = 0x00;

	va_list marker;
	va_start(marker, format);
	vsprintf_s(buffer, sizeof(buffer), format, marker);
	va_end(marker);

    this->write(std::string(buffer));
}

void Logger::writePrefix()
{
    time_t now = time(0);
    struct tm  tstruct;
    char buffer[128];
    
    tstruct = *localtime(&now);
    strftime(buffer, sizeof(buffer), "[%Y-%m-%d.%X] ", &tstruct);
    this->logFile->write(buffer, strlen(buffer));
}