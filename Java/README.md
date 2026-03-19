cd into Java folder
to compile:
    javac -cp ..\libs\jmdns-3.5.11.jar -d out src\PeerDiscovery.java

run:
    .\run.bat Bob_java

or to run without the bat file:
    java -cp "out;..\libs\jmdns-3.5.11.jar;..\libs\slf4j-api-1.7.36.jar;..\libs\slf4j-simple-1.7.36.jar" PeerDiscovery Bob_java

Replace Bob_java with whatever name you want to use for your peer.