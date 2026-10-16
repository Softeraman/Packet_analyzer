# PacketScope web demo on Vercel

The web demo wraps the existing C++ PCAP reader, packet parser, SNI/HTTP hostname extractors and application classifier. A small Python standard-library HTTP adapter accepts a capture and invokes the compiled native engine. No paid API or database is needed.

Import `main` in Vercel. `Dockerfile.vercel` builds the native executable, runs the sample/filter/validation tests and starts the web server on `PORT` (default 80). This uses Vercel's Container Runtime.

## Included

- Responsive traffic dashboard, real sample capture and file upload.
- Packet, byte, flow and application summaries.
- Block by IPv4 endpoint, application or hostname substring; rules simulate whole-flow filtering and do not change the visitor's network.
- Search the top 250 flows and export the actual report as JSON.
- Temporary upload files are deleted after analysis. No payload capture, logging or retention service is added.

## Limits

Classic PCAP 2.4, microsecond timestamps, Ethernet and IPv4 TCP/UDP. Maximum upload: 10 MB / 150,000 packets, 20-second native analysis timeout. Unsupported packets are counted separately. PCAPNG and other link types are rejected. Hostname extraction works on a complete TLS ClientHello or HTTP header in a packet; there is no TCP reassembly or payload decryption. Flow classification is heuristic. Counts reflect captured bytes, not measured live bandwidth. Only use synthetic captures without personal traffic.

## Local build

```sh
g++ -std=c++17 -O2 -Iinclude src/web_analyzer.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp -o web_analyzer
python web/test_engine.py
python web/server.py
```

Open `http://localhost:8081`. On Windows build `web_analyzer.exe` and set `ANALYZER_BINARY` to its absolute path before running the Python server/tests.
