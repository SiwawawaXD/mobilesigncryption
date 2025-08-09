# Group Digital Signature on a Mobile Cloud with Signcryption and EdDSA

We have created a signcryption scheme that use X25519 encryption and Ed25519 for group digital signature signing. Google cloud is used to off-load unnecessary tasks that doesn't need to run on mobile to run on cloud to reduce the the load on mobile device.

#### Please Note, We used Google Cloud as a cloud service for our experiment. As for other cloud service, the instruction may be different.

## Set up

To use all component of this project, follow these steps. 

### Create databases on Google CloudSQL

1. Go to https://console.cloud.google.com/sql/instances. and create a new instance.
2. Go to `Overview` page of the instance and import the database from Project/SourceCode/cloud
3. Go to `Users` page of the instance and add user account for a Flask application.

### Set up Flask application

1. Go to and open the file Project/SourceCode/cloud/FlaskApp/app.yaml
2. In the following variables, they can be found at following location
    CLOUD_SQL_USERNAME: Can be found in `Users` page. Use the name created in previous process.
    CLOUD_SQL_PASSWORD: Use password for the CLOUD_SQL_USERNAME
    CLOUD_SQL_DATABASE_NAME: Can be found in `Cloud SQL Studio` page. It is the name of the imported database.
    CLOUD_SQL_CONNECTION_NAME: Can be found in `Overview page`. at the `Connect to this instance` window. in `Connection name` field.
* *Please note that the variables that we left there is no longer available*

### Deploy app on Google Cloud

1. Download and install Google Cloud SDK at https://cloud.google.com/sdk/docs/install
2. Open a terminal at Project/SourceCode/cloud/FlaskApp
3. Run gcloud init. and choose suitable options for the app.
4. Run gcloud app deploy and follow its instruction to upload project to cloud and deploy it.

### Mobile set up

To use Sender.jar and Receiver.jar on mobile device like in desktop, Termux is needed. Termux is an application that combines powerful terminal emulation with an extensive Linux package collection. Follow these steps to make Termux able to run .jar file. 

1. Install Termux from Google Playstore. https://play.google.com/store/apps/details?id=com.termux&hl=en
2. Open Termux and run 
    $ pkg install openjdk-21
   to install OpenJDK which is required to run .jar file.
3. Move the Sender.jar and Receiver.jar into Termux, this can be done in file manager and other file managing application. Select open with another application and select Termux. Files will be put into downloads directory of Termux.
* *If want to send and receive file to the same device, put Sender.jar and Receiver.jar in different folder for easier clarification. Use mkdir command to create directory and cp to copy file*

### Sender.jar usage.

To send a message to a receiver, follow these steps. 

1. Go to a directory that stored Sender.jar in Termux then run
    $ java -jar Sender.jar
2. The following output will appear

    what do you want to do? press
    1 - Sign up (keygen)
    2 - Create group signature
    3 - Send a message
    4 - Load private key to program (required when restart program)
    5 - Exit program

  For first time use, Press 1 to generate digital signature keys and encryption keys. If not using for the first time, press 4 to load keys into the program.
3. Create a group signature by pressing 2. Enter group name and Group member ID. Enter each member ID one by one. and stop by enter 0. Group member ID is ID of Senders in the group to be create. Each user has their own ID after sign up(e.g. 1,22,34). User can press 4 to check it again. 
4. Send a message(file) to receiver by pressing 3. First, enter the group name sender want to represent as and that group should have the sender in group member. Then, Enter receiver's ID. If receiver key is not generated yet, generate a key for receiver first. Next, Enter file name for example, computer.pdf. Next, Enter group name to select a group key to sign. After this the file is encrypted, signed and sent to cloud. Sender can see url of encrypted file in Google Cloud Storage and detail of encryption and signing operation at the output. This is done for Sender side.

### Receiver.jar usage.

To receiver a message from a sender, follow these steps. 

1. Go to a directory that stored Receiver.jar in Termux then run
    $ java -jar Receiver.jar
2. The following output will appear

    what you want to do? press
    1 - Sign up (keygen)
    2 - Look at incoming messages ID
    3 - Read a message
    4 - Load private key to program (required when restart program)
    5 - Exit program

 For first time use, Press 1 to generate digital signature keys and encryption keys. If not using for the first time, press 4 to load keys into the program.
3. Press 2 to look at incoming message ID for the receiver. The message ID is used in `3 - Read a mesasge`
4. Press 3 to Read a message. First, enter a group name receiver want to verify the message. Enter a different group name from sender result in invalid digital signature verification result. Then, enter message ID receiver want to read. The detail of decryption can also be seen here. This is done for receiver's side.

## Miscellaneous
