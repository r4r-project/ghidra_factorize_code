package factorizecode.gui;

import java.util.Observable;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData.UpdateType;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTablePanel;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;

/**
 * This class is in charge of displaying instruction searcher
 */
public class InstructionSearchProvider extends InstructionSearchDialog {
	//
	// Instance attributes:
	//	- script<FactorizeCodeMainProvider>          : The main provider
	//	- savedSig<String>                           : The saved signature before update gui
	//	- signatureField<FunctionSignatureTextField> : The widget containing the function signature
	//	- infLabel<GDLabel>                          : The label printing infos
	//
	private FactorizeCodeMainProvider script;
	
	//
	// Constructors
	//
	public InstructionSearchProvider(FactorizeCodeMainProvider script) {
		//
		// Parameters:
		//	- script<FactorizeCode>           : The script running this window
		//	- plugin<InstructionSearchPlugin> : The searcher plugin
		//	- title<String>                   : The window title
		//	- taskMonitor<TaskMonitor>        : Task monitor
		//
		super(
			InstructionSearchUtils.getInstructionSearchPlugin(script.getTool()),
			"Instruction searcher",
			null
		);
		this.script = script;
	}

	//
	// GUI
	//
	@Override
	public void update(Observable o, Object arg) {
		//
		// Update the window on event
		//
		if (arg instanceof UpdateType) {
			UpdateType type = (UpdateType) arg;
			switch (type) {
				case RELOAD:
					this.revalidate();
					break;
				case UPDATE:
			}
		}
	}

	protected JPanel buildMainPanel() {
		//
		// Build the main panel
		//
		// Return:
		//	- JPanel : The panel
		//
		InstructionTablePanel instructionTablePanel = new InstructionTablePanel(searchData.getMaxNumOperands(), getPlugin(), this);
		JPanel mainPanel = new JPanel();

		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
		
		mainPanel.add(instructionTablePanel.getWorkPanel());
		
		this.searchData.registerForGuiUpdates(instructionTablePanel.getTable());
		
		return mainPanel;
	}
		
	@Override
	protected void revalidate() {
		//
		// Create and refresh the gui
		//
		this.removeWorkPanel();
		this.addWorkPanel(this.buildMainPanel());
	}
	
}