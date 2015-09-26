# PackerAttacker

Unpacking is the ponderous – yet essential – initial step in malware analysis. As malware mutates, evolves, and propagates, so do the packers that are used to hide their intent from static analysis techniques. For the typical malware analyst, fighting against the vast array of packing methods can be challenging; it’s almost impossible to know how every packer works. However, all packers have a common goal: to write code to memory and execute it.

We’ve created a tool, aptly named The Packer Attacker, which exploits this common feature that exists in all packers. From an injected DLL, The Packer Attacker uses memory and API hooks to monitor when a sample writes to its PE sections, allocates new memory, or executes within heap memory that has been given executable privileges. When any of these events culminate in a way that resembles expected packer behavior, the targeted memory page(s) are dumped to disk, accompanied by detailed logs of what caused the dump.

For it's memory hooks, The Packer Attacker limits access rights to tracked pages and uses a Vectored Exception Handler to catch ACCESS_VIOLATION exceptions when the memory is written to or executed. For it's API hooks, the tool uses Microsoft Research's Detours library. The injected DLL will also propagate itself into new processes and track when code is unpacked to remote processes.

In our tests, The Packer Attacker has been able to pull full PE executables from active samples of many high-profile malware families (CryptoLocker, CryptoWall, Citroni, Zues, Citadel, and TeslaCrypt). In blind tests against an unknown variety of malware from a large malware repository, The Packer Attacker showed promising results, defeating both known packers (like UPX) and unknown packers.
