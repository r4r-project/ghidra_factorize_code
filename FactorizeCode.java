//
// TODO:
//  - Comments :)
//  - Search how to link instruction block to function
//  - Stabilize
//  - Create a plugin
//  - Auto detect inline functions and try to factorize code
//

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;

import javax.swing.JPanel;

import ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData.UpdateType;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTablePanel;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchApi;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.TaskMonitor;

public class FactorizeCode extends GhidraScript {
	
	private String funcName;
	
	private class MyInstructionSearchDialog extends InstructionSearchDialog {

		private FactorizeCode script;
		
		public MyInstructionSearchDialog(FactorizeCode script, InstructionSearchPlugin plugin, String title, TaskMonitor taskMonitor) {
			super(plugin, title, taskMonitor);
			this.script = script;
		}

		@Override
		protected JPanel createWorkPanel() {
			InstructionTablePanel instructionTablePanel =
				new InstructionTablePanel(searchData.getMaxNumOperands(), getPlugin(), this);

			JPanel mainPanel = new JPanel();
			mainPanel.setLayout(new BorderLayout());
			mainPanel.add(instructionTablePanel.getWorkPanel());
			this.searchData.registerForGuiUpdates(instructionTablePanel.getTable());
			
			return mainPanel;
		}

		@Override
		public void update(Observable o, Object arg) {
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

		@Override
		protected void revalidate() {
			this.removeWorkPanel();
			this.addWorkPanel(this.createWorkPanel());
			
			if(this.applyButton == null) {
				this.addApplyButton();
				this.applyButton.setText("Search for factorize");
			}
			
			if(this.cancelButton == null) {
				this.addCancelButton();
			}		
		}
		
		//
		// Core (NON GUI YEEEEEEEESSSS)
		//
		@Override
		protected void applyCallback() {
			List<InstructionMetadata> meta = new ArrayList<InstructionMetadata>();
			Instruction curInstr;
			long blockSize;
			int transaction;
			
			meta = this.searchData.getInstructions();
			if(meta.size() == 0) {
				return;
			}
			
			blockSize = meta.get(meta.size()-1).getAddr().getOffset() - meta.get(0).getAddr().getOffset();
			this.script.printf("Instruction block size : %d\n", blockSize);

			meta = new ArrayList<InstructionMetadata>();
			
			this.script.println("Pattern finding");
			for(AddressRange range: this.script.currentProgram.getMemory().getLoadedAndInitializedAddressSet().getAddressRanges()) {
				this.script.printf("\tSegment: %s - %s\n", range.getMinAddress().toString(), range.getMaxAddress().toString());
				meta.addAll(this.searchData.search(this.script.currentProgram, range, monitor));
			}

			this.script.printf("Founded : %d\n", meta.size());
			for(InstructionMetadata m: meta) {
				
				curInstr = this.script.getInstructionAt(m.getAddr());
				if(curInstr != null) {
					//
					// Not always exactly matching pattern
					//
					transaction = this.script.currentProgram.startTransaction(String.format("AtFrom: %s - %s\n", m.getAddr().toString(), m.getAddr().add(blockSize).toString()));
					this.script.setPreComment(
						m.getAddr(), 
						"#".repeat(this.script.funcName.length() + 4)
						+ String.format("\n# %s #\n", this.script.funcName)
					);
					this.script.setPostComment(
						m.getAddr().add(blockSize), 
						"#".repeat(this.script.funcName.length() + 4)
					);
					this.script.currentProgram.endTransaction(transaction, true);
					this.script.printf("\tAtFrom: %s - %s\n", m.getAddr().toString(), m.getAddr().add(blockSize).toString());
				} else {
					//
					// Not always non matching pattern
					//
					this.script.printf("\t%s : Possibly not disassembled or inter-instructions\n", m.getAddr().toString());
				}
			}
		}
	}
	
	@Override
	protected void run() throws Exception {
		
		//
		// Get all required parameters
		//
		this.funcName = askString("Function name", "Please enter the function name to assign to this inline");
		PluginTool tool = this.state.getTool();
		InstructionSearchDialog searchDialog = new MyInstructionSearchDialog(
			this,
			InstructionSearchUtils.getInstructionSearchPlugin(tool), 
			"Searched pattern to factorize", 
			null
		);
		tool.showDialog(searchDialog);
	}
	
}
