# Unhook_from_memory

Remove EDR hooks established in NTDLL by EDRs.

<br /> 1. Create suspended process (32 or 64 bits)
<br /> 2. Parse the _PEB structure
<br /> 3. Look for PE32 magic bytes
<br /> 4. Iterate over all loaded modules in the suspended process.
<br /> The first will be the application (suspended) module.
<br /> The second will be the NTDLL 
<br /> 5. Look for .text section in the NTDLL loaded in the suspended process
<br /> 6. Copy the .text section from the suspended process to the target process (implant).
<br /> 7. Have fun!!

<br /> 
