// Headless Ghidra post-script: decompile one or more functions and write the C-like output to a file.
//
// Usage (see docs/tools/ghidra/decompile.ps1):
//   analyzeHeadless C:\Tools\ghidra_projects FFT0 -process fftype0hd.exe.unpacked.exe -noanalysis
//       -scriptPath <this dir> -postScript DecompileAt.java <outFile> <addr1> [<addr2> ...]
// Addresses are hex, with or without 0x, as full VAs (0x140371A20) or RVAs (0x371A20).
//@category FFT0

import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileAt extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			println("usage: DecompileAt <outFile> <addr> [<addr> ...]");
			return;
		}
		long base = currentProgram.getImageBase().getOffset();
		DecompInterface ifc = new DecompInterface();
		ifc.toggleCCode(true);
		ifc.openProgram(currentProgram);
		try (PrintWriter out = new PrintWriter(new FileWriter(args[0]))) {
			for (int i = 1; i < args.length; i++) {
				String s = args[i].toLowerCase().startsWith("0x") ? args[i].substring(2) : args[i];
				long v = Long.parseUnsignedLong(s, 16);
				if (v < base) v += base; // RVA given
				Address addr = toAddr(v);
				Function f = getFunctionContaining(addr);
				if (f == null) {
					out.println("// " + addr + ": no function here");
					continue;
				}
				DecompileResults res = ifc.decompileFunction(f, 120, new ConsoleTaskMonitor());
				out.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " (asked " + addr + ") =====");
				if (res.decompileCompleted())
					out.println(res.getDecompiledFunction().getC());
				else
					out.println("// decompile failed: " + res.getErrorMessage());
				out.println();
			}
		}
		ifc.dispose();
		println("written " + args[0]);
	}
}
