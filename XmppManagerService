package com.visikard.arm.service.impl;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;

import org.jivesoftware.smack.Chat;
import org.jivesoftware.smack.ChatManager;
import org.jivesoftware.smack.ChatManagerListener;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.ConnectionListener;
import org.jivesoftware.smack.MessageListener;
import org.jivesoftware.smack.PacketListener;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.filter.PacketFilter;
import org.jivesoftware.smack.filter.PacketTypeFilter;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.Presence.Type;
import org.jivesoftware.smackx.ChatState;
import org.jivesoftware.smackx.filetransfer.FileTransferListener;
import org.jivesoftware.smackx.filetransfer.FileTransferManager;
import org.jivesoftware.smackx.filetransfer.OutgoingFileTransfer;
import org.jivesoftware.smackx.packet.ChatStateExtension;
import org.jivesoftware.smackx.packet.Nick;
import org.jivesoftware.smackx.packet.VCard;

import org.jivesoftware.smack.AccountManager;
import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.PacketCollector;
import org.jivesoftware.smack.Roster;
import org.jivesoftware.smack.RosterEntry;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.filter.AndFilter;
import org.jivesoftware.smack.filter.PacketIDFilter;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Registration;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smackx.Form;
import org.jivesoftware.smackx.muc.MultiUserChat;

import com.visikard.arm.common.Constants;
import com.visikard.arm.util.Util;
import com.visikard.arm.util.Utilitys;

public class XmppManagerService {

	private static final Logger logger = Logger.getLogger(XmppManagerService.class);
	private static final int packetReplyTimeout = 1000; // millis
	private static String server = "";
	private static int port = 5280;
	private ConnectionConfiguration config;
	private XMPPConnection connection;
	private static XmppManagerService clientMnger = null;
	// private ChatManager chatManager;
	// private MessageListener messageListener;
	public static String defaultPassword = "123456";
	
	public static XmppManagerService getInstance() {
					
		try {
			
			server = Constants.VISIKARD_CHAT_SERVER_HOST;
			port = NumberUtils.toInt(Constants.VISIKARD_CHAT_SERVER_PORT);
			defaultPassword = Constants.TOKEN_KEY_PASSWORK_CHAT;
			
			if(clientMnger == null) {				
				clientMnger = new XmppManagerService();
				clientMnger.init();
				String userName = "";
				if(Util.getLoginedUser().getMerchantInfo() != null) {
					userName = String.valueOf(Util.getLoginedUser().getMerchantInfo().getIdKards());
				}
				clientMnger.performLogin(userName, defaultPassword);
			}
		} catch (XMPPException e) {
			// TODO Auto-generated catch block			
			logger.debug("XMPP ERROR "+ Utilitys.getStackTraceString(e, ""));
		} finally {
			logger.info("Create Instance Chat ok!");
		}
		
		return clientMnger;
	}

	public void init() throws XMPPException {
		try {
			Thread.sleep(2000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			logger.debug(String.format(
					"Initializing connection to server %1$s port %2$d", server,
					port));
			SmackConfiguration.setPacketReplyTimeout(packetReplyTimeout);
			config = new ConnectionConfiguration(server, port);
			config.setSASLAuthenticationEnabled(false);
			config.setSecurityMode(SecurityMode.disabled);
			config.setReconnectionAllowed(true);
			connection = new XMPPConnection(config);
			connection.connect();
			System.out.print("\nConnected: " + connection.isConnected());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// chatManager = connection.getChatManager();
		// messageListener = new MyMessageListener();
	}

	public void performLogin(String username, String password)
			throws XMPPException {
		try {
			if (connection != null && connection.isConnected()) {

				connection.login(username, password);
				System.out.print("\n LOGIN  :" + username);
			}
		} catch (Exception e) {
			System.out.print("\n connects Exception :" + username + ", exc :"
					+ e.toString());
		}
		System.out.print("\n Login Connected: " + connection.getUser());
	}

	public XMPPConnection getConnection() {
		return connection;
	}

	public void setConnection(XMPPConnection connection) {
		this.connection = connection;
	}

	/*
	 * public void setStatus(boolean available, String status) { Presence.Type
	 * type = available? Type.available: Type.unavailable; Presence presence =
	 * new Presence(type); presence.setStatus(status);
	 * connection.sendPacket(presence); }
	 */
	public void destroy() {
		if (connection != null && connection.isConnected()) {

			Presence offlinePres = new Presence(Presence.Type.unavailable);
			connection.sendPacket(offlinePres);

			connection.disconnect();
			clientMnger = null;
			logger.debug("Disconnected");
			System.out.print("\n Disconnected");

		}

	}

	/*
	 * public void sendMessage(String message, String buddyJID) throws
	 * XMPPException {
	 * logger.debug(String.format("Sending mesage '%1$s' to user %2$s", message,
	 * buddyJID)); Chat chat = chatManager.createChat(buddyJID,
	 * messageListener); chat.sendMessage(message);
	 * 
	 * }
	 */
	/*
	 * public void createEntry(String user, String name) throws Exception {
	 * 
	 * logger.debug(String.format("Creating entry for buddy '%1$s' with name %2$s"
	 * , user, name));
	 * 
	 * Roster roster = connection.getRoster();
	 * 
	 * roster.setSubscriptionMode(Roster.SubscriptionMode.accept_all);
	 * 
	 * roster.createEntry(user, name, null);
	 * 
	 * }
	 */

	public boolean createAccount1(String username, String nickname,
			String password, String email) throws XMPPException {

		Map<String, String> newRegAttrMap = new HashMap<String, String>();

		newRegAttrMap.put("name", nickname);
		newRegAttrMap.put("email", email);

		String newStatus = "";
		try {
			AccountManager manager = connection.getAccountManager();

			logger.debug("supportsAccountCreation is "
					+ manager.supportsAccountCreation());
			if (password == "")
				password = defaultPassword;
			manager.createAccount(username, password, newRegAttrMap);

		} catch (XMPPException e) {
			// Print error message
			newStatus = "UNABLE TO REGISTER";

			final XMPPError error = e.getXMPPError();
			int errorCode = 0;
			if (error != null) {
				errorCode = error.getCode();

				// Print errorDetails

				newStatus += "  (ERROR-DETAILS [" + errorCode + ":- "
						+ error.getMessage() + "]";
			}
			logger.debug(newStatus);

			return false;
		}
		return true;
	}

	public synchronized void makeFriend(String myusername, String mypassword,
			String friendusername, String friendNick) throws Exception {
		// subscribe to a new user
		try {
			// check if the user is already on the roster
			performLogin(myusername, mypassword);
			Roster roster = connection.getRoster();
			// roster.createGroup("Friends");

			printRoster();

			if (roster == null
					|| !roster.getEntries().toString()
							.contains(friendusername + "@")) {
				roster.setSubscriptionMode(Roster.SubscriptionMode.manual);

				// System.out.print("\n ok1");
				Presence subscribe = new Presence(Presence.Type.subscribe);
				subscribe.setTo(friendusername + "@" + server);
				connection.sendPacket(subscribe);
				// logout
				destroy();
				// System.out.print("\n ok2");
				// When Bob receives the request, he approves it:
				// login
				connection = null;
				init();
				performLogin(friendusername, mypassword);
				Presence subscribed = new Presence(Presence.Type.subscribed);
				subscribed.setTo(myusername + "@" + server);
				connection.sendPacket(subscribed);
				// logout
				// destroy();
				// System.out.print("\n ok3");
				// login
				// init();
				// performLogin(friendusername, mypassword);
				Presence subscribe1 = new Presence(Presence.Type.subscribe);
				subscribe1.setTo(myusername + "@" + server);
				connection.sendPacket(subscribe1);
				// logout
				destroy();
				// System.out.print("\n ok4");
				// login

				connection = null;
				Thread.sleep(2000);
				init();
				performLogin(myusername, mypassword);
				Presence subscribed1 = new Presence(Presence.Type.subscribed);
				subscribed1.setTo(friendusername + "@" + server);
				connection.sendPacket(subscribed1);

				// System.out.print("\n ok5");
				destroy();
				connection = null;

				/*
				 * logger.debug("add user on the roster");
				 * System.out.println("add user on the roster:" +
				 * friendusername); Presence subscribed = new
				 * Presence(Presence.Type.subscribed);
				 * subscribed.setTo(friendusername+"@"+server);
				 * connection.sendPacket(subscribed);
				 */
				/*
				 * roster = connection.getRoster(); Thread.sleep(10000);
				 * roster.createEntry(friendusername+"@"+server, friendNick,
				 * null); System.out.print("\n ok6");
				 */
				// printRoster();
			} else {
				destroy();
				// user already on the roster
				System.out.print("\n user already on the roster");
			}
		} catch (Exception ex) {
			destroy();

			System.out.print("\n can not make friend into chat :"
					+ ex.toString());
		}
	}

	// public boolean addFriend(String jid) {
	// String nickname = null;
	// String idExtension = jid+"@"+server;
	// Roster roster = connection.getRoster();
	// nickname = StringUtils.parseBareAddress(jid);
	// if (!roster.contains(idExtension)) {
	// try {
	// roster.setSubscriptionMode(Roster.SubscriptionMode.accept_all);
	// roster.createEntry(idExtension, nickname, null);
	// //to subscribe the user in the entry
	// Presence subscribe = new Presence(Presence.Type.subscribe);
	// subscribe.setTo(idExtension);
	// connection.sendPacket(subscribe);
	// logger.debug("add user on the roster");
	// return true;
	//
	// } catch (XMPPException e) {
	// System.err.println("Error in adding friend");
	// return false;
	// }
	// } else {
	// return false;
	// }
	// }

	public void unFriend(String Jid) throws Exception {
		// subscribe to a new user

		// check if the user is already on the roster
		Roster roster = connection.getRoster();
		String message = "";
		try {
			String idExtension = Jid + "@" + server;

			RosterEntry rosterEntry = roster.getEntry(idExtension);
			logger.debug("rosterEntryy" + rosterEntry.toString());

			roster.removeEntry(rosterEntry);
			message = "You have denied the friend request";
		} catch (XMPPException e) {
			e.printStackTrace();
			message = "Exception";
		}
		logger.debug(message);

	}

	public boolean deletetUser(String username, String password)
			throws Exception {

		String newStatus = "";
		try {
			performLogin(username, password);
			AccountManager manager = connection.getAccountManager();
			manager.deleteAccount();
		} catch (XMPPException e) {
			// Print error message
			newStatus = "UNABLE TO Delete";

			final XMPPError error = e.getXMPPError();
			int errorCode = 0;
			if (error != null) {
				errorCode = error.getCode();

				// Print errorDetails

				newStatus += "  (ERROR-DETAILS [" + errorCode + ":- "
						+ error.getMessage() + "]";
			}
			logger.debug(newStatus);

			return false;
		}
		return true;
	}

	public void joinRoom(String roomName, String userId, String password)
			throws Exception {
		// Create a MultiUserChat using a Connection for a room
		MultiUserChat muc = new MultiUserChat(connection, roomName);

		// Create the room
		muc.join(userId, password);

		// Send an empty room configuration form which indicates that we want
		// an instant room
		muc.sendConfigurationForm(new Form(Form.TYPE_SUBMIT));

		logger.debug("" + muc.getMembers().toArray());

		boolean isRunning = true;
		while (isRunning) {

			Thread.sleep(50);
		}

	}

	public void createRoom(String roomname) {
		try {
			MultiUserChat muc;
			connection.connect();
			// connection.login("1120", "123456");
			muc = new MultiUserChat(connection,
					"testroom3@conference.chat.visikard.vn");
			muc.create("jsm");

			muc.sendConfigurationForm(new Form(Form.TYPE_SUBMIT));

		} catch (XMPPException e) {

			e.printStackTrace();

		}

	}

	public void printRoster() throws Exception {

		Roster roster = connection.getRoster();

		Collection<RosterEntry> entries = roster.getEntries();

		for (RosterEntry entry : entries) {

			logger.debug(String.format("Buddy:%1$s - Status:%2$s",

			entry.getName(), entry.getStatus()));

		}

	}

	/*
	 * 
	 * public static void runAddUser(final Long fkKard,final String
	 * nickname,final String password, final String email){ new Thread(){ public
	 * void run(){ try{ XmppManager xmppManager = new
	 * XmppManager(Contants.OPENFIRE_SERVERNAME, 5222); xmppManager.init();
	 * xmppManager.createAccount(""+fkKard, nickname, password, email);
	 * logger.error("call runAddUser fkKard - "+ fkKard ); boolean isRunning =
	 * true; while (isRunning) { Thread.sleep(50); }
	 * 
	 * xmppManager.destroy(); }catch (Exception e) {
	 * logger.error("Error when call runAddUser: "+ e.toString());} } }.start();
	 * 
	 * }
	 * 
	 * public static void runAddFriend(final Long myKardId,final String
	 * myPassword, final Long kardFriendId, final String friendNick){ new
	 * Thread(){ public void run(){ try{ XmppManager xmppManager = new
	 * XmppManager(Contants.OPENFIRE_SERVERNAME, 5222); //XmppManager
	 * xmppManager = new XmppManager("chat.visikard.vn", 5222);
	 * xmppManager.init(); //xmppManager.performLogin(""+myKardId,myPassword);
	 * xmppManager.makeFriend(""+myKardId,myPassword,""+kardFriendId,
	 * friendNick);
	 * 
	 * logger.error("call runAddFriend myKardId:kardFriendId - "+ myKardId +
	 * " : "+ kardFriendId); boolean isRunning = true; while (isRunning) {
	 * Thread.sleep(50); }
	 * 
	 * xmppManager.destroy(); }catch (Exception e) {
	 * logger.error("Error when call runAddFriend: "+ e.toString());} }
	 * }.start();
	 * 
	 * }
	 * 
	 * public static void runUnFriend(final Long myKardId,final String
	 * myPassword, final Long kardFriendId){ new Thread(){ public void run(){
	 * try{ XmppManager xmppManager = new
	 * XmppManager(Contants.OPENFIRE_SERVERNAME, 5222); xmppManager.init();
	 * xmppManager.performLogin(""+myKardId,myPassword);
	 * xmppManager.unFriend(""+kardFriendId);
	 * logger.error("call runUnFriend myKardId:kardFriendId - "+ myKardId +
	 * " : "+ kardFriendId); boolean isRunning = true; while (isRunning) {
	 * Thread.sleep(50); }
	 * 
	 * xmppManager.destroy(); }catch (Exception e) {
	 * logger.error("Error when call runUnFriend: "+ e.toString());} }
	 * }.start();
	 * 
	 * }
	 * 
	 * public static void runDeleteUser(final Long fkKard, final String
	 * password){ new Thread(){ public void run(){ try{ XmppManager xmppManager
	 * = new XmppManager(Contants.OPENFIRE_SERVERNAME, 5222);
	 * xmppManager.init(); xmppManager.deletetUser(""+fkKard, password);
	 * logger.error("call runDeleteUser fkKard: - "+ fkKard ); boolean isRunning
	 * = true; while (isRunning) { Thread.sleep(50); }
	 * 
	 * xmppManager.destroy(); }catch (Exception e) {
	 * logger.error("Error when call runDeleteUser: "+ e.toString());} }
	 * }.start();
	 * 
	 * }
	 */
	/*
	 * class MyMessageListener implements MessageListener {
	 * 
	 * @Override public void processMessage(Chat chat, Message message) {
	 * 
	 * String from = message.getFrom();
	 * 
	 * String body = message.getBody();
	 * 
	 * logger.debug(String.format("Received message '%1$s' from %2$s", body,
	 * from)); } }
	 */
	public void changeURL(String userIdkard, String pass, String url)
			throws XMPPException {
		performLogin(userIdkard, pass);
		Registration reg = new Registration();
		reg.setType(IQ.Type.SET);
		reg.setTo(connection.getServiceName());
		Map<String, String> map = new HashMap<String, String>();
		map.put("username", StringUtils.parseName(connection.getUser()));
		map.put("url", url);
		reg.setAttributes(map);
		PacketFilter filter = new AndFilter(new PacketIDFilter(
				reg.getPacketID()), new PacketTypeFilter(IQ.class));
		PacketCollector collector = connection.createPacketCollector(filter);
		connection.sendPacket(reg);
		IQ result = (IQ) collector.nextResult(SmackConfiguration.getPacketReplyTimeout());
		// Stop queuing results
		collector.cancel();
		if (result == null) {
			logger.error("No response from server.");
		} else if (result.getType() == IQ.Type.ERROR) {
			logger.error(result.getError());
		}
	}
}
