/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * TODO: ALL THE BACKEND :)
 */

package factorizecode;

import factorizecode.gui.FactorizeCodeMainProvider;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.DataService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

/**
 * This plugin implement a code factorizer
 */
//@formatter:off
@PluginInfo(
	status           = PluginStatus.UNSTABLE,
	category         = PluginCategoryNames.USER_ANNOTATION,
	packageName      = FactorizeCodeConfig.PACKAGE_NAME,
	shortDescription = FactorizeCodeConfig.SHORT_DESCRIPTION,
	description      = FactorizeCodeConfig.DESCRIPTION,
	servicesRequired = { TableService.class, DataService.class, DataTypeManagerService.class }
)
//@formatter:on
public class FactorizeCodePlugin extends ProgramPlugin {
	private FactorizeCodeMainProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public FactorizeCodePlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	protected void programActivated(Program p) {
		super.programActivated(p);
		this.provider = new FactorizeCodeMainProvider(this);
	}
	
}
