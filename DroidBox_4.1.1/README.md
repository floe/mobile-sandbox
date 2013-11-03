DroidBox 4.1.1
==============

1. Export the path for the android SDK tools

        export PATH=$PATH:/path/to/android-sdk/tools/
        export PATH=$PATH:/path/to/android-sdk/platform-tools/

2. Clone this repo to your local hard disk and uncompress the two files inside the images directory

3. Setup a new AVD targeting Android 4.1.2 and choose Nexus 4 as device by running:

        android 

4. Start the emulator with the new AVD:

        ./startemu.sh <AVD name>

5. When emulator has booted up, start analyzing samples:

        ./droidbox.sh <file.apk>

6. Stop the analysis with ctr-c