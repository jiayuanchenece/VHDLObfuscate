# VHDLObfuscate
Obfuscator for VHDL modules

## Usage
```
vhdl_obfuscate [-dc] input_file salt
```
Note: Same salt will produce same obfuscation (on same file).

## Before
```vhdl
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

-- Uncomment the following library declaration if using
-- arithmetic functions with Signed or Unsigned values
--use IEEE.NUMERIC_STD.ALL;

-- Uncomment the following library declaration if instantiating
-- any Xilinx primitives in this code.
--library UNISIM;
--use UNISIM.VComponents.all;

entity lfsr32_mod is
    Port ( CLK_IN 		: in  STD_LOGIC;
           SEED_IN 		: in  STD_LOGIC_VECTOR(31 downto 0);
           SEED_EN_IN 	: in  STD_LOGIC;
           VAL_OUT 		: out STD_LOGIC_VECTOR(31 downto 0));
end lfsr32_mod;

architecture Behavioral of lfsr32_mod is

signal lfsr_reg : std_logic_vector(31 downto 0) := X"00000000";

begin

	VAL_OUT <= lfsr_reg;

	process(CLK_IN)
	begin
		if rising_edge(CLK_IN) then
			if SEED_EN_IN = '1' then
				lfsr_reg <= SEED_IN;
			else
				lfsr_reg(31 downto 1) <= lfsr_reg(30 downto 0);
				lfsr_reg(0) <= not(lfsr_reg(31) XOR lfsr_reg(21) XOR lfsr_reg(1) XOR lfsr_reg(0)); 
			end if;
		end if;	
	end process;

end Behavioral;
```

## After
```vhdl
library IEEE; use IEEE.STD_LOGIC_1164.ALL; entity s_0bbaa0f98479 is Port ( s_5305cfe61f9a72359d968d43a222fc : in STD_LOGIC; s_eec65d39e19f18089661d8ea5f7551ece773d7b0b75b4026b14323f549ae305f 
: in STD_LOGIC_VECTOR(31 downto 0); s_0edee3567bb5c : in STD_LOGIC; s_aa18a83cbd0534470fe1707eb2b75f2e4aff62d7ea9b56e625d6 : out STD_LOGIC_VECTOR(31 downto 
0)); end s_0bbaa0f98479; architecture Behavioral of s_0bbaa0f98479 is signal s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1 : std_logic_vector(31 downto 
0) := X"00000000"; begin process(s_5305cfe61f9a72359d968d43a222fc) begin if rising_edge(s_5305cfe61f9a72359d968d43a222fc) then end if; if rising_edge(s_5305cfe61f9a72359d968d43a222fc) 
then if s_0edee3567bb5c = '1' then s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1 <= s_eec65d39e19f18089661d8ea5f7551ece773d7b0b75b4026b14323f549ae305f;
 else s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1(31 downto 1) <= s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1(30 downto 0); s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1(0) 
<= not(s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1(31) XOR s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1(21) XOR s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1(1) 
XOR s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1(0)); end if; end if; end process; s_aa18a83cbd0534470fe1707eb2b75f2e4aff62d7ea9b56e625d6 <= s_9356edaff716b2ba8d3d53f767d802e00f2b8e12eb19f1;
```

## Operations
- remove_all_comments : removes all comments
- move_non_process_blocks_to_end : moves combinator logic to end of file
- swap_process_blocks : shuffles order of process blocks (x3)
- merge_process_blocks : merges certain process blocks (x3)
- split_process_blocks : splits certain process blocks (x3)
- obfusticate_key_words : obfuscates all key words
- remove_whitespace : removes whitespace
- generate_encapsulation_file : generates VHDL file which encapsulates obfuscated module
