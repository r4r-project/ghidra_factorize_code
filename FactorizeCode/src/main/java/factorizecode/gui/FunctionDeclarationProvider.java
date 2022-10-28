package factorizecode.gui;

import factorizecode.FactorizeCodePlugin;
import ghidra.app.plugin.core.function.editor.FunctionEditorDialog;
import ghidra.app.services.DataTypeManagerService;
import ghidra.util.UndefinedFunction;

/**
 * This class provide function signature
 */
public class FunctionDeclarationProvider extends FunctionEditorDialog {
	private FactorizeCodeMainProvider mainProvider;

	/**
	 * @param mainProvider The main level provider
	 */
	public FunctionDeclarationProvider(FactorizeCodeMainProvider mainProvider) {
		super(
			mainProvider.getPlugin().getTool().getService(DataTypeManagerService.class),
			new UndefinedFunction(
				mainProvider.getPlugin().getCurrentProgram(),
				mainProvider.getPlugin().getCurrentProgram().getMinAddress()
			)
		);
		this.mainProvider = mainProvider;
	}
		
	/*
	 * Getters
	 */
	private FactorizeCodePlugin getPlugin() {
		return this.mainProvider.getPlugin();
	}
}
