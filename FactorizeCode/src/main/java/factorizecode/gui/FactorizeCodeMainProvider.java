package factorizecode.gui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import factorizecode.FactorizeCodeConfig;
import factorizecode.FactorizeCodePlugin;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.framework.plugintool.PluginTool;

/**
 * This class is the main content provider of our plugin
 */
public class FactorizeCodeMainProvider extends DialogComponentProvider {
	private FactorizeCodePlugin plugin;
	private DockingAction action;
	private int indexOfPanel;
	private JPanel mainPanel;
	private JPanel currentPanel;
	private JButton nextButton;
	private JButton previousButton;
	private JButton applyButton;
	private JPanel[] panels;
	private InstructionSearchProvider instructionSearchProvider;
	private FunctionDeclarationProvider functionDeclarationProvider;
	//private JPanel functionDeclarationProvider;
	
	/**
	 * @param tool  The plugin tools
	 * @param name  The provider name
	 */
	public FactorizeCodeMainProvider(FactorizeCodePlugin plugin) {
		super(plugin.getName(), false);
		this.plugin       = plugin;
		this.indexOfPanel = 0;
		this.buildUI();
		this.setProperties();
		this.createActions();
	}

	/**
	 * Build all the UI
	 */
	private void buildUI() {
		JPanel buttons;
		
		// Create main panel
		this.mainPanel = new JPanel(new BorderLayout());
		
		// Create providers for instruction search 
		// pattern and function declaration
		this.instructionSearchProvider   = new InstructionSearchProvider(this);
		this.functionDeclarationProvider = new FunctionDeclarationProvider(this);
		//this.functionDeclarationProvider = new JPanel();
		this.panels = new JPanel[] {
			(JPanel)this.instructionSearchProvider.getComponent(),
			(JPanel)this.functionDeclarationProvider.getComponent()
			//this.functionDeclarationProvider
		};
		
		// Set viewable panels
		this.currentPanel = new JPanel(new CardLayout());
		for(JPanel p: this.panels) {
			this.currentPanel.add(p);
		}
		
		// Create buttons and panel containing them
		buttons = new JPanel(new GridLayout(1, 3));
		
		this.previousButton = new JButton("Previous");
		this.previousButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				previousPanel();
				updateApplyButton();
			}
			
		});

		this.nextButton = new JButton("Next");
		this.nextButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				nextPanel();
				updateApplyButton();
			}
			
		});

		this.applyButton = new JButton("Apply");
		this.applyButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				apply();
			}
			
		});
		this.applyButton.setEnabled(false);
		
		buttons.add(this.previousButton);
		buttons.add(this.nextButton);
		buttons.add(this.applyButton);
		
		// Dispatch in main panel
		this.mainPanel.add(this.currentPanel, BorderLayout.CENTER);
		this.mainPanel.add(buttons, BorderLayout.SOUTH);
	}

	/**
	 * Set all UI properties
	 */
	private void setProperties() {
		this.setTitle(FactorizeCodeConfig.TITLE);
		this.setTransient(true);
	}
	
	/**
	 * Create actions to provide display of this UI
	 */
	private void createActions() {
		this.action = new NavigatableContextAction(this.getTitle(), this.getTitle()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				getTool().showDialog(getThis(), context.getComponentProvider());
			}
		};
		this.action.addToWindowWhen(NavigatableActionContext.class);
		this.action.setMenuBarData(new MenuData(new String[] {
				ToolConstants.MENU_TOOLS, "Factorize code"
		}));
		this.action.setDescription(FactorizeCodeConfig.SHORT_DESCRIPTION);
		this.action.setEnabled(true);
		
		this.getTool().addAction(this.action);
	}
	
	/**
	 * Switch to previous panel
	 */
	private void previousPanel() {
		CardLayout cur = (CardLayout)this.currentPanel.getLayout();
		this.nextButton.setEnabled(true);
		this.indexOfPanel--;
		cur.previous(this.currentPanel);
		if(this.indexOfPanel == 0) {
			this.previousButton.setEnabled(false);
		}
	}
	
	/**
	 * Switch to next panel
	 */
	private void nextPanel() {
		CardLayout cur = (CardLayout)this.currentPanel.getLayout();
		this.previousButton.setEnabled(true);
		this.indexOfPanel++;
		cur.next(this.currentPanel);
		if(this.indexOfPanel+1 == this.panels.length) {
			this.nextButton.setEnabled(false);
		}
	}
	
	/**
	 * Update the ability to click on the apply button
	 */
	private void updateApplyButton() {
		// TODO: Implement checks
	}

	/**
	 * Apply the action with provided parameters
	 */
	private void apply() {
		// TODO: Implement apply
	}
	
	/*
	 * Getters
	 */
	
	@Override
	public JComponent getComponent() {
		return this.mainPanel;
	}

	public FactorizeCodeMainProvider getThis() {
		return this;
	}
	
	public FactorizeCodePlugin getPlugin() {
		return this.plugin;
	}

	public PluginTool getTool() {
		return this.getPlugin().getTool();
	}

}
