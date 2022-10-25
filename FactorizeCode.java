//
//@author aiglematth
//@category 
//@keybinding
//@menupath
//@toolbar
//

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData.UpdateType;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTablePanel;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.TaskMonitor;


import static java.awt.Color.blue;
import static java.awt.Color.red;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;

import docking.actions.KeyBindingUtils;
import ghidra.util.Swing;

public class FactorizeCode extends GhidraScript {
	
	private String funcName;
	
	//
	// Copied from https://github.com/NationalSecurityAgency/ghidra/blob/da94eb86bd2b89c8b0ab9bd89e9f0dc5a3157055/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/editor/FunctionSignatureTextField.java
	//
	class FunctionSignatureTextField extends JTextPane {
		private static final String ENTER_ACTION_NAME = "ENTER";
		private static final String ESCAPE_ACTION_NAME = "ESCAPE";
		private static final String TAB_ACTION_NAME = "TAB";
		public Color DEFAULT_COLOR = Color.black;
		public Color PARAMETER_NAME_COLOR = new Color(155, 50, 155);
		public Color FUNCTION_NAME_COLOR = blue;
		public Color ERROR_NAME_COLOR = red;

		private StyledDocument doc;
		private SimpleAttributeSet paramNameAttributes;
		private SimpleAttributeSet functionNameAttributes;
		private SimpleAttributeSet defaultAttributes;
		private ActionListener actionListener;
		private ActionListener escapeListener;
		private ActionListener tabListener;
		private ChangeListener changeListener;
		private SimpleAttributeSet errorAttributes;

		FunctionSignatureTextField() {
			Font myFont = getFont();
			setFont(myFont.deriveFont(24.0f));
			doc = getStyledDocument();
			AttributeSet inputAttributes = getInputAttributes();

			paramNameAttributes = new SimpleAttributeSet(inputAttributes);
			StyleConstants.setForeground(paramNameAttributes, PARAMETER_NAME_COLOR);

			functionNameAttributes = new SimpleAttributeSet(inputAttributes);
			StyleConstants.setForeground(functionNameAttributes, FUNCTION_NAME_COLOR);

			errorAttributes = new SimpleAttributeSet(inputAttributes);
			StyleConstants.setForeground(errorAttributes, ERROR_NAME_COLOR);

			defaultAttributes = new SimpleAttributeSet(inputAttributes);
			StyleConstants.setForeground(defaultAttributes, DEFAULT_COLOR);
			doc.addDocumentListener(new DocumentListener() {

				@Override
				public void removeUpdate(DocumentEvent e) {
					updateColors();
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					clearAttributes(e.getOffset(), e.getLength());
					updateColors();
				}

				@Override
				public void changedUpdate(DocumentEvent e) {
					// do nothing
				}
			});

			// add enter processing to the TextPane
			Action enterAction = new AbstractAction(ENTER_ACTION_NAME) {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (actionListener != null) {
						actionListener.actionPerformed(e);
					}
				}
			};
			KeyStroke enter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0);
			KeyBindingUtils.registerAction(this, enter, enterAction, JComponent.WHEN_FOCUSED);
			KeyBindingUtils.registerAction(this, enter, enterAction, JComponent.WHEN_IN_FOCUSED_WINDOW);

			// add escape processing to the TextPane
			Action escapeAction = new AbstractAction(ESCAPE_ACTION_NAME) {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (escapeListener != null) {
						escapeListener.actionPerformed(e);
					}
				}
			};
			KeyStroke escape = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
			KeyBindingUtils.registerAction(this, escape, escapeAction, JComponent.WHEN_FOCUSED);
			KeyBindingUtils.registerAction(this, escape, escapeAction,
				JComponent.WHEN_IN_FOCUSED_WINDOW);

			// add escape processing to the TextPane
			Action tabAction = new AbstractAction(TAB_ACTION_NAME) {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (tabListener != null) {
						tabListener.actionPerformed(e);
					}
				}
			};
			KeyStroke tab = KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0);
			KeyBindingUtils.registerAction(this, tab, tabAction, JComponent.WHEN_FOCUSED);
			KeyBindingUtils.registerAction(this, tab, tabAction, JComponent.WHEN_IN_FOCUSED_WINDOW);
		}

		void setActionListener(ActionListener listener) {
			this.actionListener = listener;
		}

		void setEscapeListener(ActionListener listener) {
			this.escapeListener = listener;
		}

		void setTabListener(ActionListener listener) {
			this.tabListener = listener;
		}

		private void updateColors() {
			Swing.runLater(() -> {
				String text = getText();
				List<ColorField> computeColors = computeColors(text);
				if (computeColors != null) {
					doc.setCharacterAttributes(0, text.length(), defaultAttributes, true);
					for (ColorField colorField : computeColors) {
						doc.setCharacterAttributes(colorField.start, colorField.length(),
							colorField.attributes, true);
					}
				}
				notifyChange();
			});
		}

		void clearAttributes(final int start, final int length) {
			Swing.runLater(() -> doc.setCharacterAttributes(start, length, defaultAttributes, true));
		}

		void notifyChange() {
			if (changeListener != null) {
				changeListener.stateChanged(new ChangeEvent(this));
			}
		}

		void setChangeListener(ChangeListener listener) {
			this.changeListener = listener;
		}

		List<ColorField> computeColors(String text) {
			List<ColorField> list = new ArrayList<>();
			int functionRightParenIndex = text.lastIndexOf(')');
			int functionLeftParenIndex = findMatchingLeftParenIndex(text, functionRightParenIndex);
			if (functionLeftParenIndex < 0) {
				return null;
			}
			List<Integer> paramStartStopIndexes =
				findParamStartStopindexes(text, functionLeftParenIndex, functionRightParenIndex);

			if (paramStartStopIndexes == null) {
				return null;
			}

			SubString substring = new SubString(text, 0, functionLeftParenIndex).trim();
			SubString functionName = getLastWord(substring);
			if (functionName == null) {
				return null;
			}

			list.add(
				new ColorField(functionName.getStart(), functionName.getEnd(), functionNameAttributes));
			for (int i = 0; i < paramStartStopIndexes.size() - 1; i++) {
				int start = paramStartStopIndexes.get(i) + 1;
				int end = paramStartStopIndexes.get(i + 1);
				SubString paramString = new SubString(text, start, end);
				paramString = paramString.trim();
				if (paramString.toString().equals("...")) {
					continue;
				}
				if (paramString.toString().equals("void")) {
					continue;
				}
				// check for empty param list
				if (paramString.length() == 0 && paramStartStopIndexes.size() == 2) {
					break;
				}
				SubString paramName = getLastWord(paramString);
				if (paramName == null) {
					break;
				}
				while (paramName.length() > 0 && paramName.charAt(0) == '*') {
					paramName = paramName.substring(1);

				}
				list.add(new ColorField(paramName.getStart(), paramName.getEnd(), paramNameAttributes));
			}
			return list;
		}

		private SubString getLastWord(SubString string) {
			int lastIndexOf = string.lastIndexOf(' ');
			if (lastIndexOf < 0) {
				return null;
			}
			return string.substring(lastIndexOf + 1);
		}

		private List<Integer> findParamStartStopindexes(String text, int startIndex, int endIndex) {
			List<Integer> commaIndexes = new ArrayList<>();
			int templateCount = 0;
			commaIndexes.add(startIndex);
			for (int i = startIndex + 1; i < endIndex; i++) {
				char c = text.charAt(i);
				if (c == '<') {
					templateCount++;
				}
				else if (c == '>') {
					templateCount--;
				}
				else if (c == ',' && templateCount == 0) {
					commaIndexes.add(i);
				}
			}
			if (templateCount != 0) {
				return null;
			}
			commaIndexes.add(endIndex);
			return commaIndexes;
		}

		private class ColorField {
			int start;
			int end;
			AttributeSet attributes;

			ColorField(int start, int end, AttributeSet attributes) {
				this.start = start;
				this.end = end;
				this.attributes = attributes;
			}

			public int length() {
				return end - start;
			}
		}

		private int findMatchingLeftParenIndex(String text, int lastRightParenIndex) {
			int parenLevel = 1;
			for (int i = lastRightParenIndex - 1; i >= 0; i--) {
				char c = text.charAt(i);
				if (c == ')') {
					parenLevel++;
				}
				else if (c == '(') {
					parenLevel--;
					if (parenLevel == 0) {
						return i;
					}
				}
			}
			return -1;
		}

		private class SubString {
			private String text;
			private int subStringStart;
			private int subStringEnd;

			SubString(String text, int start, int end) {
				this.text = text;
				this.subStringStart = start;
				this.subStringEnd = end;
			}

			public char charAt(int i) {
				return text.charAt(subStringStart + i);
			}

			public int length() {
				return subStringEnd - subStringStart;
			}

			public int getEnd() {
				return subStringEnd;
			}

			public int getStart() {
				return subStringStart;
			}

			public SubString substring(int start) {
				return new SubString(text, subStringStart + start, subStringEnd);
			}

			@Override
			public String toString() {
				return text.substring(subStringStart, subStringEnd);
			}

			public int lastIndexOf(char c) {
				for (int i = subStringEnd - 1; i >= subStringStart; i--) {
					if (text.charAt(i) == c) {
						return i - subStringStart;
					}
				}
				return -1;
			}

			public SubString trim() {
				int start = subStringStart;
				int end = subStringEnd;
				while (text.charAt(start) == ' ' && start < end) {
					start++;
				}
				while (text.charAt(end - 1) == ' ' && start < end) {
					end--;
				}

				if (start == subStringStart && end == subStringEnd) {
					return this;
				}
				return new SubString(text, start, end);
			}
		}

		void setError(final int position, final int length) {
			Swing.runLater(() -> doc.setCharacterAttributes(position, length, errorAttributes, true));
		}
	}
	
	//
	//
	//
	
	private class MyInstructionSearchDialog extends InstructionSearchDialog {
		//
		// This class extends InstructionSearchDialog to permit instruction
		// choose and masking, and factorization launching
		//
		
		//
		// Instance attributes:
		//	- script<FactorizeCode>                      : The script running this window
		//	- savedSig<String>                           : The saved signature before update gui
		//	- signatureField<FunctionSignatureTextField> : The widget containing the function signature
		//	- infLabel<GDLabel>                          : The label printing infos
		//
		private FactorizeCode script;
		private String savedSig;
		private FunctionSignatureTextField signatureField;
		private GDLabel infLabel;
		
		//
		// Constructors
		//
		public MyInstructionSearchDialog(FactorizeCode script, InstructionSearchPlugin plugin, String title, TaskMonitor taskMonitor) {
			//
			// Parameters:
			//	- script<FactorizeCode>           : The script running this window
			//	- plugin<InstructionSearchPlugin> : The searcher plugin
			//	- title<String>                   : The window title
			//	- taskMonitor<TaskMonitor>        : Task monitor
			//
			super(plugin, title, taskMonitor);
			this.script = script;
		}

		//
		// GUI
		//
		protected void info(String m) {
			//
			// Set info label text
			//
			// Parameters:
			//	- m<String> : The message
			//
			this.infLabel.setText(m);
		}
		
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

			this.infLabel = new GDLabel("");

			mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
			
			mainPanel.add(instructionTablePanel.getWorkPanel());
			mainPanel.add(this.buildFunctionSignaturePanel());
			mainPanel.add(this.infLabel);
			
			this.searchData.registerForGuiUpdates(instructionTablePanel.getTable());
			
			return mainPanel;
		}
		
		protected JPanel buildFunctionSignaturePanel() {
			//
			// Build the function signature panel
			//
			// Return:
			//	- JPanel : The panel
			//
			JPanel signaturePanel  = new JPanel();
			GDLabel signatureLabel = new GDLabel("Function signature:");

			signatureField = new FunctionSignatureTextField();
			signatureField.setText(this.savedSig == null ? "" : this.savedSig);

			signaturePanel.setLayout(new BoxLayout(signaturePanel, BoxLayout.X_AXIS));

			signaturePanel.add(signatureLabel);
			signaturePanel.add(signatureField);

			signaturePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

			return signaturePanel;
		}
		
		@Override
		protected void revalidate() {
			//
			// Create and refresh the gui
			//
			this.savedSig = this.signatureField == null ? "" : this.signatureField.getText();
			this.removeWorkPanel();
			this.addWorkPanel(this.buildMainPanel());
			
			if(this.applyButton == null) {
				this.addApplyButton();
				this.applyButton.setText("Search for factorize");
			}
			
			if(this.cancelButton == null) {
				this.addCancelButton();
			}		
		}
		
		//
		// Non GUI
		//
		public FunctionDefinitionDataType getSignature() {
			//
			// Get function signature provided in the window
			//
			// Return:
			//	- FunctionDefinitionDataType : The signature or null if error occurs
			//
			String sig = this.signatureField.getText();
			FunctionSignatureParser parser = new FunctionSignatureParser(
				this.script.currentProgram.getDataTypeManager(), 
				this.script.state.getTool().getService(DataTypeManagerService.class)
			);
			try {
				return parser.parse(null, sig == null ? "" : sig);
			} catch(Exception e) {}
			return null;
		}
		
		@Override
		protected void applyCallback() {
			//
			// Whats happen when apply button is clicked
			//
			// Description:
			//	- (1) : Get selected instructions
			//	- (2) : Compute offset between last instruction in the block and the first one
			//	- (3) : Get all all matching instructions from all address ranges in the current program
			//	- (4) : Create comments for existing instructions
			//
			List<InstructionMetadata> meta    = new ArrayList<InstructionMetadata>();
			FunctionDefinitionDataType sigDef = this.getSignature();
			int factorized = 0;
			String sig;
			int sigSize;
			Instruction curInstr;
			long lastInstructionOffset;
			int transaction;
			
			if(sigDef == null) {
				this.info("You should provide a valid function signature");
				return;
			}
			sig     = sigDef.getPrototypeString();
			sigSize = sig.length();
			
			this.signatureField.setText(sig);
			
			// (1)
			meta = this.searchData.getInstructions();
			if(meta.size() == 0) {
				return;
			}
			
			// (2)
			lastInstructionOffset = meta.get(meta.size()-1).getAddr().getOffset() - meta.get(0).getAddr().getOffset();
			this.script.printf("Last instruction offset : +%d\n", lastInstructionOffset);

			meta = new ArrayList<InstructionMetadata>();
			
			// (3)
			this.script.println("Pattern finding");
			for(AddressRange range: this.script.currentProgram.getMemory().getLoadedAndInitializedAddressSet().getAddressRanges()) {
				this.script.printf("\tSegment: %s - %s\n", range.getMinAddress().toString(), range.getMaxAddress().toString());
				meta.addAll(this.searchData.search(this.script.currentProgram, range, monitor));
			}

			// (4)
			this.script.printf("Founded : %d\n", meta.size());
			for(InstructionMetadata m: meta) {
				
				curInstr = this.script.getInstructionAt(m.getAddr());
				if(curInstr != null) {
					//
					// Not always exactly matching pattern
					//
					transaction = this.script.currentProgram.startTransaction(String.format("AtFrom: %s - %s\n", m.getAddr().toString(), m.getAddr().add(lastInstructionOffset).toString()));
					this.script.setPreComment(
						m.getAddr(), 
						"#".repeat(sigSize + 4)
						+ String.format("\n# %s #\n", sig)
					);
					this.script.setPostComment(
						m.getAddr().add(lastInstructionOffset), 
						"#".repeat(sigSize + 4)
					);
					this.script.currentProgram.endTransaction(transaction, true);
					this.script.printf("\tAtFrom: %s - %s\n", m.getAddr().toString(), m.getAddr().add(lastInstructionOffset).toString());
					factorized++;
				} else {
					//
					// Not always non matching pattern
					//
					this.script.printf("\t%s : Possibly not disassembled or inter-instructions\n", m.getAddr().toString());
				}
			}
			
			this.info(String.format("Result: %d block(s) factorized", factorized));
		}
	}
	
	@Override
	protected void run() throws Exception {
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
