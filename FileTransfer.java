import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class FileTransfer {

	public static void main(String[] args) {
		if (args[0].equals("makekeys")) {
			try {
				KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
				gen.initialize(4096); // you can use 2048 for faster key generation
				KeyPair keyPair = gen.genKeyPair();
				PrivateKey privateKey = keyPair.getPrivate();
				PublicKey publicKey = keyPair.getPublic();
				try (ObjectOutputStream oos = new ObjectOutputStream(
						new FileOutputStream(new File("public.bin")))) {
					oos.writeObject(publicKey);
				}
				try (ObjectOutputStream oos = new ObjectOutputStream(
						new FileOutputStream(new File("private.bin")))) {
					oos.writeObject(privateKey);
				}
			} catch (NoSuchAlgorithmException | IOException e) {
				e.printStackTrace(System.err);
			}

		} else if (args[0].equals("server")) {
			try {
				ServerSocket serverSocket = new ServerSocket(Integer.parseInt(args[2]));
				while (true) {
					Socket acceptedRequest = serverSocket.accept();
					ObjectOutputStream output = new ObjectOutputStream(acceptedRequest.getOutputStream());
					ObjectInputStream input = new ObjectInputStream(acceptedRequest.getInputStream());
					String path = null;
					int chunkSize = 1024, nextExpected = 0, numberOfChunks = 0;
					byte[] encryptedKey = null, totalData = new byte[0];
					Key sessionKey = null;
					Message message = (Message)input.readObject();
					while (message.getType() != MessageType.DISCONNECT && nextExpected < numberOfChunks) {
						if (message.getType() == MessageType.START) {
							StartMessage start = (StartMessage)message;
							path = start.getFile();
							chunkSize = start.getChunkSize();
							encryptedKey = start.getEncryptedKey();
							File file = new File(path);
							if (!file.exists()) {
								AckMessage errorAck = new AckMessage(-1);
								output.writeObject(errorAck);
								message = (Message)input.readObject();
								continue;
							}
							numberOfChunks = (int) (file.length() / chunkSize) +
									((file.length() % chunkSize == 0) ? 0 : 1);
							ObjectInputStream ois = new ObjectInputStream(
									new FileInputStream(new File(args[1])));
							PrivateKey privateKey2 = (PrivateKey)ois.readObject();
							ois.close();
							Cipher cipher = Cipher.getInstance("AES");
							cipher.init(Cipher.UNWRAP_MODE, privateKey2);
							sessionKey = cipher.unwrap(encryptedKey, "AES", Cipher.PRIVATE_KEY);
							AckMessage response = new AckMessage(0);
							output.writeObject(response);
							message = (Message)input.readObject();
						} else if (message.getType() == MessageType.STOP) {
							AckMessage stopAck = new AckMessage(-1);
							output.writeObject(stopAck);
							break;
						} else if (message.getType() == MessageType.CHUNK) {
							if (sessionKey == null) {
								System.out.println("Transfer not initiated.");
								break;
							}
							Chunk currentChunk = (Chunk)message;
							if (currentChunk.getSeq() == nextExpected) {
								byte[] encryptedData = currentChunk.getData();
								int crcFromClient = currentChunk.getCrc();
								Cipher cipher = Cipher.getInstance("AES");
								cipher.init(Cipher.UNWRAP_MODE, sessionKey);
								byte[] data = cipher.doFinal(encryptedData);
								CRC32 crcGenerated = new CRC32();
								crcGenerated.update(data);
								if (crcFromClient != crcGenerated.getValue()) {
									AckMessage reSend = new AckMessage(nextExpected);
									output.writeObject(reSend);
									message = (Message)input.readObject();
									continue;
								}
								System.out.println("Chunk received [" + (nextExpected + 1) +
										"/" + numberOfChunks + "].");
								byte[] temp = totalData.clone();
								totalData = Arrays.copyOf(temp, temp.length + data.length);
								System.arraycopy(data, 0, totalData, temp.length, data.length);
								nextExpected++;
								AckMessage response = new AckMessage(nextExpected);
								output.writeObject(response);
								message = (Message)input.readObject();
							} else {
								AckMessage reSend = new AckMessage(nextExpected);
								output.writeObject(reSend);
								message = (Message)input.readObject();
							}
						}
					}
					System.out.println("Output path: output.txt");
					FileOutputStream fos = new FileOutputStream("output.txt");
					fos.write(totalData);
					fos.close();
					acceptedRequest.close();
					output.close();
					input.close();
					serverSocket.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else if (args[0].equals("client")) {
			try {
				Socket mySocket = new Socket(args[2], Integer.parseInt(args[3]));
				System.out.println("Connected to server: " + mySocket.getInetAddress());
				KeyGenerator gen = KeyGenerator.getInstance("AES");
				gen.init(128);
				SecretKey sessionKey = gen.generateKey();
				ObjectInputStream ois = new ObjectInputStream(
						new FileInputStream(new File(args[1])));
				PublicKey publicKey2 = (PublicKey)ois.readObject();
				ois.close();
				Cipher cipher1 = Cipher.getInstance("AES");
				cipher1.init(Cipher.WRAP_MODE, publicKey2);
				byte[] encryptedKey = cipher1.wrap(sessionKey);
				Scanner keyboard = new Scanner(System.in);
				System.out.print("Enter path: ");
				String pathString = keyboard.nextLine();
				File file = new File(pathString);
				while (!file.exists()) {
					System.out.print("Enter path: ");
					pathString = keyboard.nextLine();
					file = new File(pathString);
				}
				Path path = Paths.get(file.getAbsolutePath());
				byte[] message = Files.readAllBytes(path);
				System.out.print("Enter chunk size [1024]: ");
				int chunkSize = keyboard.nextInt();
				// Get the ceiling of the file length divided by the chunk size
				int numberOfChunks = (int) (file.length() / chunkSize) + ((file.length() % chunkSize == 0) ? 0 : 1);
				ObjectOutputStream output = new ObjectOutputStream(mySocket.getOutputStream());
				ObjectInputStream input = new ObjectInputStream(mySocket.getInputStream());
				StartMessage start = new StartMessage(pathString, encryptedKey, chunkSize);
				System.out.println("Sending: " + pathString + ". File size: " + file.length() + "." +
						"Sending " + numberOfChunks + " chunks.");
				output.writeObject(start);
				AckMessage response = (AckMessage)input.readObject();
				for (int nextExpected = 0; nextExpected < numberOfChunks &&
						response.getSeq() == nextExpected; nextExpected++) {
					byte[] curCh;
					// avoid Out of Bounds Exception on the last chunk of less than full size
					if (nextExpected == numberOfChunks - 1) {
						curCh = Arrays.copyOfRange(message, nextExpected * chunkSize, message.length);
					} else {
						curCh = Arrays.copyOfRange(message, nextExpected * chunkSize, (nextExpected + 1) * chunkSize);
					}
					CRC32 crcVal = new CRC32();
					crcVal.update(curCh);
					Cipher cipher2 = Cipher.getInstance("AES");
					cipher2.init(Cipher.WRAP_MODE, sessionKey);
					byte[] encryptedData = cipher2.doFinal(curCh);
					Chunk chunk = new Chunk(nextExpected, encryptedData, (int)crcVal.getValue());
					output.writeObject(chunk);
					response = (AckMessage)input.readObject();
					System.out.println("Chunks completed [" + (nextExpected + 1) + "/" + numberOfChunks + "].");
				}
				DisconnectMessage disconnect = new DisconnectMessage();
				output.writeObject(disconnect);
				keyboard.close();
				mySocket.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
			
		} else {
			System.out.println("Invalid command line arguments.");
			System.exit(0);
		}
	}
}