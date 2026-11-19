For the past few weeks I have been building an open-source scanner that checks the tool descriptions of MCP servers, and the main conclusion of this work turned out to be less about the scanner than about how little a single quality figure says.

An MCP server tells an AI agent which tools it offers, and the model reads those descriptions as instructions, which is why a command hidden in a description can make the agent read someone else's keys or send data outside.

I first measured the scanner on a published set of 485 poisoned descriptions, keeping 178 of them aside for the final check. The first version noticed 70 of those 178 attacks, or 39.3%. I then studied the misses in the rest of the set and added a rule that notices when a description gives orders about a tool its own server does not provide, and the result rose to 167 of 178, or 93.8%, with one false alarm across 160 genuine tools.

After that I ran the same version on a second set of 46 attacks written by three other authors, and it noticed 15 of them, or 32.6%. It found nearly all the attacks that use recognisable devices, such as fake system markers and invisible characters, while of the 33 attacks deliberately written in ordinary business language it noticed only 3.

From these numbers I can conclude that pattern-based rules find attacks whose wording someone has already seen, and that a high score on one dataset usually reflects how closely that dataset resembles the rules rather than how well a system is protected overall.

If you have tested your own defences on data that played no part in tuning them, I would be interested to know how far apart the results turned out to be.

#AIsecurity #MCP #cybersecurity
