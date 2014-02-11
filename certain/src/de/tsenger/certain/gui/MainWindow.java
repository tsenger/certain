package de.tsenger.certain.gui;

import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.Enumeration;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTree;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.bouncycastle.asn1.ASN1ParsingException;

import de.tsenger.certain.asn1.eac.CVCertificate;
import de.tsenger.tools.FileSystem;

public class MainWindow {

	private JFrame frame;
	private JTree tree;
	private DefaultMutableTreeNode rootNode;
	private DefaultTreeModel treeModel;
	private String lastFileChooserPath;
	
	private JLabel lblChrContent = null;
	private JLabel lblCarContent = null;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					MainWindow window = new MainWindow();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public MainWindow() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 450, 300);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new GridLayout(1, 0, 0, 0));
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setResizeWeight(0.3);
		frame.getContentPane().add(splitPane);
		
		rootNode = new DefaultMutableTreeNode("Root Node");
		treeModel = new DefaultTreeModel(rootNode);
		
		tree = new JTree(treeModel);
		tree.setRootVisible(false);
		tree.addTreeSelectionListener(new TreeSelectionListener() {
			@Override
			public void valueChanged(TreeSelectionEvent e) {
				TreePath path = e.getNewLeadSelectionPath();
			     updateInfoPane(path);
			}

		});
		tree.setFont(new Font("Courier New", Font.PLAIN, 14));
		tree.setEditable(false);
		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		tree.setShowsRootHandles(true);
		splitPane.setLeftComponent(tree);
		
		JPanel panel = new JPanel();
		splitPane.setRightComponent(panel);
		panel.setLayout(null);
		
		JLabel lblChr = new JLabel("CHR");
		lblChr.setBounds(12, 44, 50, 20);
		panel.add(lblChr);
		
		lblChrContent = new JLabel("");
		lblChrContent.setBounds(74, 44, 235, 20);
		panel.add(lblChrContent);
		
		JLabel lblCar = new JLabel("CAR");
		lblCar.setBounds(12, 12, 50, 20);
		panel.add(lblCar);
		
		lblCarContent = new JLabel("");
		lblCarContent.setBounds(74, 12, 235, 20);
		panel.add(lblCarContent);
		
		JMenuBar menuBar = new JMenuBar();
		frame.setJMenuBar(menuBar);
		
		JMenu mnFile = new JMenu("File");
		menuBar.add(mnFile);
		
		JMenuItem mntmImportCvCert = new JMenuItem("Import cv cert");
		mntmImportCvCert.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String fileName = openFileChooserAndGetFileName();
				if (fileName!=null) {
					CVCertificate cert = importCert(fileName);
					addCertificate(cert);
				}
			}
		});
		mnFile.add(mntmImportCvCert);
	}
	
	private void updateInfoPane(TreePath path) {
		DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) path.getLastPathComponent();
		
		if (treeNode.getUserObject()  instanceof CVCertificate) {
			CVCertificate cert = (CVCertificate)treeNode.getUserObject();
			lblChrContent.setText(cert.getChrString());
			lblCarContent.setText(cert.getCarString());
		}
		else {
			lblChrContent.setText("");
			lblCarContent.setText("");
		}
		
	}
	
	private DefaultMutableTreeNode addCertificate(CVCertificate child) {
		
	    DefaultMutableTreeNode parentNode = null;
	
	    if (doesAlreadyExistInTree(child)) return null;
	    
	    parentNode = searchParentNode(child);

	    if (parentNode == null) parentNode = rootNode;

	    return addCertificate(parentNode, child, true);
	}
	
	private DefaultMutableTreeNode addCertificate(DefaultMutableTreeNode parent, CVCertificate child, boolean shouldBeVisible) {
		
		String chr = child.getChrString();

		DefaultMutableTreeNode childNode = new DefaultMutableTreeNode(chr);
		childNode.setUserObject(child);
		
		treeModel.insertNodeInto(childNode, parent, parent.getChildCount());

		//Make sure the user can see the lovely new node.
		if (shouldBeVisible) {
			tree.scrollPathToVisible(new TreePath(childNode.getPath()));
		}
		return childNode;
	}
	
	private boolean doesAlreadyExistInTree(CVCertificate certToSearch) {		
		DefaultMutableTreeNode node = null;
	    CVCertificate cert = null;
	    
	    Enumeration e = rootNode.breadthFirstEnumeration();
		
		while (e.hasMoreElements()) {
			node = (DefaultMutableTreeNode) e.nextElement();
			
			if (node.getUserObject() instanceof CVCertificate) {
				cert = (CVCertificate) node.getUserObject();
				if (cert.getChrString().equals(certToSearch.getChrString())) {
					return true;
				}
			}
		}
		return false;
		
	}
	
	private DefaultMutableTreeNode searchParentNode(CVCertificate certToSearch) {
		DefaultMutableTreeNode node = null;
	    CVCertificate cert = null;
	    
	    Enumeration e = rootNode.breadthFirstEnumeration();
		
		while (e.hasMoreElements()) {
			node = (DefaultMutableTreeNode) e.nextElement();
			
			if (node.getUserObject() instanceof CVCertificate) {
				cert = (CVCertificate) node.getUserObject();
				if (cert.getChrString().equals(certToSearch.getCarString())) {
					return node;
				}
			}
		}
		return null;
	}
	
	private String openFileChooserAndGetFileName() {
		JFileChooser fc = new JFileChooser(lastFileChooserPath);

	    int state = fc.showOpenDialog( null );

	    if ( state == JFileChooser.APPROVE_OPTION )
	    {
	    	File file = fc.getSelectedFile();
	    	lastFileChooserPath = file.getAbsolutePath();
	    	return file.getPath();
	    }
	    else
	      return null;
	}
	
	private CVCertificate importCert(String fileName) {
		CVCertificate cvCert = null;			
		try {
			byte[] tempCvcBytes = FileSystem.readFile(fileName);
			cvCert = CVCertificate.getInstance(tempCvcBytes);
		} catch (ASN1ParsingException e) {
			System.out.println(e.getLocalizedMessage());
			return null;
		} catch (IOException e) {
			System.out.println(e.getLocalizedMessage());
			return null;
		}	
		
		return cvCert;
	}

}
