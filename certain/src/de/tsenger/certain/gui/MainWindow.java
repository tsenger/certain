package de.tsenger.certain.gui;

import java.awt.Color;
import java.awt.Component;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.Enumeration;

import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTree;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
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
	private JLabel lblRoleDescriptionContent = null;
	private JLabel lblTerminalTypeContent = null;
	private JLabel lblEffectiveDateContent = null;
	private JLabel lblExpirationDateContent = null;
	
	// Custom TreeCellRenderer for changing icons dynamicly
	final CertainTreeCellRenderer renderer = new CertainTreeCellRenderer();



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
		frame.setBounds(100, 100, 700, 600);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new GridLayout(1, 0, 0, 0));
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setResizeWeight(0.6);
		frame.getContentPane().add(splitPane);
		
		rootNode = new DefaultMutableTreeNode("Root Node");
		treeModel = new DefaultTreeModel(rootNode);
		
		JPanel rightPanel = new JPanel();
		rightPanel.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "certifcate info", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		splitPane.setRightComponent(rightPanel);
		GridBagLayout gbl_rightPanel = new GridBagLayout();
		gbl_rightPanel.columnWidths = new int[]{50, 235, 0};
		gbl_rightPanel.rowHeights = new int[]{20, 20, 0, 0, 0, 0, 0, 0, 0};
		gbl_rightPanel.columnWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		gbl_rightPanel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		rightPanel.setLayout(gbl_rightPanel);
		
		JLabel lblCar = new JLabel("CAR");
		GridBagConstraints gbc_lblCar = new GridBagConstraints();
		gbc_lblCar.fill = GridBagConstraints.BOTH;
		gbc_lblCar.insets = new Insets(0, 0, 5, 5);
		gbc_lblCar.gridx = 0;
		gbc_lblCar.gridy = 1;
		rightPanel.add(lblCar, gbc_lblCar);
		
		lblCarContent = new JLabel("");
		GridBagConstraints gbc_lblCarContent = new GridBagConstraints();
		gbc_lblCarContent.fill = GridBagConstraints.BOTH;
		gbc_lblCarContent.insets = new Insets(0, 0, 5, 0);
		gbc_lblCarContent.gridx = 1;
		gbc_lblCarContent.gridy = 1;
		rightPanel.add(lblCarContent, gbc_lblCarContent);
		
		JLabel lblChr = new JLabel("CHR");
		GridBagConstraints gbc_lblChr = new GridBagConstraints();
		gbc_lblChr.fill = GridBagConstraints.BOTH;
		gbc_lblChr.insets = new Insets(0, 0, 5, 5);
		gbc_lblChr.gridx = 0;
		gbc_lblChr.gridy = 2;
		rightPanel.add(lblChr, gbc_lblChr);
		
		lblChrContent = new JLabel("");
		GridBagConstraints gbc_lblChrContent = new GridBagConstraints();
		gbc_lblChrContent.insets = new Insets(0, 0, 5, 0);
		gbc_lblChrContent.fill = GridBagConstraints.BOTH;
		gbc_lblChrContent.gridx = 1;
		gbc_lblChrContent.gridy = 2;
		rightPanel.add(lblChrContent, gbc_lblChrContent);
		
		JLabel lblRoleDescription = new JLabel("Role Description");
		GridBagConstraints gbc_lblRoleDescription = new GridBagConstraints();
		gbc_lblRoleDescription.anchor = GridBagConstraints.WEST;
		gbc_lblRoleDescription.insets = new Insets(0, 0, 5, 5);
		gbc_lblRoleDescription.gridx = 0;
		gbc_lblRoleDescription.gridy = 3;
		rightPanel.add(lblRoleDescription, gbc_lblRoleDescription);
		
		lblRoleDescriptionContent = new JLabel("");
		GridBagConstraints gbc_lblRoleDescriptionContent = new GridBagConstraints();
		gbc_lblRoleDescriptionContent.insets = new Insets(0, 0, 5, 0);
		gbc_lblRoleDescriptionContent.gridx = 1;
		gbc_lblRoleDescriptionContent.gridy = 3;
		rightPanel.add(lblRoleDescriptionContent, gbc_lblRoleDescriptionContent);
		
		JLabel lblTerminalType = new JLabel("Terminal Type");
		GridBagConstraints gbc_lblTerminalType = new GridBagConstraints();
		gbc_lblTerminalType.anchor = GridBagConstraints.WEST;
		gbc_lblTerminalType.insets = new Insets(0, 0, 5, 5);
		gbc_lblTerminalType.gridx = 0;
		gbc_lblTerminalType.gridy = 4;
		rightPanel.add(lblTerminalType, gbc_lblTerminalType);
		
		lblTerminalTypeContent = new JLabel("");
		GridBagConstraints gbc_lblTerminalTypeContent = new GridBagConstraints();
		gbc_lblTerminalTypeContent.insets = new Insets(0, 0, 5, 0);
		gbc_lblTerminalTypeContent.gridx = 1;
		gbc_lblTerminalTypeContent.gridy = 4;
		rightPanel.add(lblTerminalTypeContent, gbc_lblTerminalTypeContent);
		
		JLabel lblEffectiveDate = new JLabel("Effective Date");
		GridBagConstraints gbc_lblEffectiveDate = new GridBagConstraints();
		gbc_lblEffectiveDate.anchor = GridBagConstraints.WEST;
		gbc_lblEffectiveDate.insets = new Insets(0, 0, 5, 5);
		gbc_lblEffectiveDate.gridx = 0;
		gbc_lblEffectiveDate.gridy = 6;
		rightPanel.add(lblEffectiveDate, gbc_lblEffectiveDate);
		
		lblEffectiveDateContent = new JLabel("");
		GridBagConstraints gbc_lblEffectiveDateContent = new GridBagConstraints();
		gbc_lblEffectiveDateContent.insets = new Insets(0, 0, 5, 0);
		gbc_lblEffectiveDateContent.gridx = 1;
		gbc_lblEffectiveDateContent.gridy = 6;
		rightPanel.add(lblEffectiveDateContent, gbc_lblEffectiveDateContent);
		
		JLabel lblExpirationDate = new JLabel("Expiration Date");
		GridBagConstraints gbc_lblExpirationDate = new GridBagConstraints();
		gbc_lblExpirationDate.anchor = GridBagConstraints.WEST;
		gbc_lblExpirationDate.insets = new Insets(0, 0, 0, 5);
		gbc_lblExpirationDate.gridx = 0;
		gbc_lblExpirationDate.gridy = 7;
		rightPanel.add(lblExpirationDate, gbc_lblExpirationDate);
		
		lblExpirationDateContent = new JLabel("");
		GridBagConstraints gbc_lblExpirationDateContent = new GridBagConstraints();
		gbc_lblExpirationDateContent.gridx = 1;
		gbc_lblExpirationDateContent.gridy = 7;
		rightPanel.add(lblExpirationDateContent, gbc_lblExpirationDateContent);
		
		JPanel leftPanel = new JPanel();
		leftPanel.setBorder(new TitledBorder(null, "certificate tree", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		leftPanel.setBackground(Color.WHITE);
		splitPane.setLeftComponent(leftPanel);
   
		
		tree = new JTree(treeModel);
		leftPanel.add(tree);
		tree.setRootVisible(false);
		tree.addTreeSelectionListener(new TreeSelectionListener() {
			@Override
			public void valueChanged(TreeSelectionEvent e) {
				TreePath path = e.getNewLeadSelectionPath();
				
				if (path==null) return;
				DefaultMutableTreeNode treeNode = (DefaultMutableTreeNode) path.getLastPathComponent();
				
				if (treeNode.getUserObject()  instanceof CVCertificate) {
					CVCertificate cert = (CVCertificate)treeNode.getUserObject();
					updateInfoPanel(cert);
			    }
			}

		});
		tree.setFont(new Font("Courier New", Font.PLAIN, 14));
		tree.setEditable(false);
		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		tree.setShowsRootHandles(true);
		tree.setCellRenderer(renderer);
		
		JMenuBar menuBar = new JMenuBar();
		frame.setJMenuBar(menuBar);
		
		JMenu mnFile = new JMenu("File");
		menuBar.add(mnFile);
		
		JMenuItem mntmImportCvCert = new JMenuItem("Import cv cert");
		mntmImportCvCert.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String fileName = null;
				File[] files = openFileChooserAndGetFiles();
				for (int i=0; i<files.length; i++) {
					fileName = files[i].getAbsolutePath();
					if (fileName!=null) {
						CVCertificate cert = importCert(fileName);
						addCertificate(cert);
					}
				}
				reorderTree();
			}
		});
		mnFile.add(mntmImportCvCert);
		
		JMenu mnEdit = new JMenu("Edit");
		menuBar.add(mnEdit);
		
		JMenuItem mntmResortTree = new JMenuItem("resort tree");
		mntmResortTree.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				reorderTree();
			}
		});
		mnEdit.add(mntmResortTree);
		
		JMenuItem mntmClearTree = new JMenuItem("clear tree");
		mntmClearTree.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				rootNode.removeAllChildren();
		        treeModel.reload();
			}
		});
		mnEdit.add(mntmClearTree);
	}
	
	private void updateInfoPanel(CVCertificate cert) {
		
		
		if (cert!=null) {
			lblChrContent.setText(cert.getChrString());
			lblCarContent.setText(cert.getCarString());
			lblRoleDescriptionContent.setText(cert.getRoleDescription());
			lblTerminalTypeContent.setText(cert.getBody().getCertificateHolderAuthorization().getTerminalTypeDescription());
			try {
				lblEffectiveDateContent.setText(cert.getEffectiveDate().toString());
				lblExpirationDateContent.setText(cert.getExpirationDate().toString());
			} catch (IOException e) {}
			
		}
		else {
			lblChrContent.setText("");
			lblCarContent.setText("");
		}
		
	}
	
	private DefaultMutableTreeNode addCertificate(CVCertificate certicateToInsert) {
		
	    DefaultMutableTreeNode parentNode = null;
	    DefaultMutableTreeNode newNode = null;
	
	    if (certicateToInsert==null) return null;
	    if (doesAlreadyExistInTree(certicateToInsert)) return null;
	    
	    parentNode = searchParentNode(certicateToInsert);

	    if (parentNode == null) parentNode = rootNode;
	    
	    newNode = addCertificate(parentNode, certicateToInsert, true);
	    return newNode;
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
	
	private void reorderTree() {
		DefaultMutableTreeNode node = null;
		DefaultMutableTreeNode parentNode = null;
		CVCertificate cert = null;
		
		for (int e=0;e<rootNode.getChildCount();e++) {
			node = (DefaultMutableTreeNode) rootNode.getChildAt(e);
			
			if (node.getUserObject() instanceof CVCertificate) {
				cert = (CVCertificate) node.getUserObject();
				parentNode = searchParentNode(cert);
				if (parentNode!=null&&node!=parentNode) {
					treeModel.removeNodeFromParent(node);
					treeModel.insertNodeInto(node, parentNode, 0);
					reorderTree();
					return;
				}
			}
		}
		return;
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
	
	private File[] openFileChooserAndGetFiles() {
		JFileChooser fc = new JFileChooser(lastFileChooserPath);
		fc.setMultiSelectionEnabled(true);
	    int state = fc.showOpenDialog( null );

	    if ( state == JFileChooser.APPROVE_OPTION )
	    {
	    	File[] files = fc.getSelectedFiles();
	    	lastFileChooserPath = files[0].getAbsolutePath();
	    	return files;
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
		} catch (IllegalArgumentException e) {
			System.out.println(e.getLocalizedMessage());
			return null;
		}
		
		return cvCert;
	}

}

@SuppressWarnings("serial") 
class CertainTreeCellRenderer extends DefaultTreeCellRenderer{

    private static ImageIcon iconCVCA = new ImageIcon("res/images/database_key.png");
    private static ImageIcon iconDV = new ImageIcon("res/images/vcard.png");
    private static ImageIcon iconTerminal = new ImageIcon("res/images/computer.png");
    private static ImageIcon iconUnknown = new ImageIcon("res/images/help.png");


    @Override
	public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded,  boolean leaf, int row, boolean hasFocus){

        Component ret = super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
        JLabel label = (JLabel) ret ;

        DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
        if (node.getUserObject() instanceof CVCertificate) {
        	CVCertificate cert = (CVCertificate) node.getUserObject();
        	String role = cert.getRoleDescription();
        		if (role!= null) {
        			if (role.equals("CVCA")) label.setIcon( iconCVCA ) ;
        			else if (role.equals("TERMINAL")) label.setIcon( iconTerminal ) ;
        			else label.setIcon( iconDV ) ;
        		}
        		else label.setIcon( iconUnknown ) ;
        }
        
        return ret;
    }
}
