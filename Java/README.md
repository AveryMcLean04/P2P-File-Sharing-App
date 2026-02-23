Java Client Side

## Requirements
- Java 17+
- Maven OR VS Code "Extension Pack for Java" by Microsoft

## Building
Open the Java folder with the Extension Pack for Java installed. VS Code will detect the pom.xml file and download the dependencies automatically.

OR

If Maiven is installed:
```bash
mvn compile
```

## Running

Open `MdnsListener.java` and click the **Run** button above the `main` method in VS Code, or:
```bash
mvn exec:java -Dexec.mainClass="MdnsListener"
```

In a second terminal, run the announcer:
```bash
mvn exec:java -Dexec.mainClass="MdnsAnnouncer"
```

If successful, the listener terminal will print `Peer found: MyPeer`.

### Firewall Note (Windows)

On first run, Windows Firewall will ask for permission to allow Java network access. Click **Allow**, and ensure both **Private** and **Public** are checked for Java in your Windows Defender Firewall settings.

## Status

- [x] mDNS peer discovery
- [ ] TCP socket communication between peers
- [ ] Mutual authentication
- [ ] Encrypted file transfer
- [ ] And more...