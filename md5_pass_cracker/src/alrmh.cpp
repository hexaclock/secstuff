#include "lab2.h"

void alrmh(int sig)
{
  std::cout << "Time exceeded, flushing buffers and exiting..." << std::endl;
  for (auto it = gl.solved.begin(); it != gl.solved.end(); ++it)
    gl.results << gl.uhashes.at(it->first) << ':' << it->second << std::endl; 
  if (gl.results.is_open())
    gl.results.close();
  std::cout << "Elapsed time: "<< time(0) - gl.start_time << std::endl; 
  std::cout << "Number of passwords tried: " << gl.pwgens << std::endl;
  exit(2);
}
