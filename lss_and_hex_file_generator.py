import sys, subprocess

def generate_files(file_list : list[str]) -> int:
    for cur_file in file_list:
        try:
            with open(f'{cur_file}.txt', 'w') as outfile:
                subprocess.run(['.\customasm.exe', f'.\\{cur_file}.asm', '-p'], stdout=outfile, check=True);
                subprocess.run(['.\customasm.exe', f'.\\{cur_file}.asm', '-f', 'list,base:16,group:6,between:" "', '-o', f'{cur_file}.hex'], check=True);
        except Exception as e:
            print(f'Error: {e}');
            return 1;
    return 0;

def main():
    asm_files = [];
    for arg in sys.argv[1:]:
        asm_files.append(arg);
    if(generate_files(asm_files) != 0):
        sys.exit(1)
    
if __name__ == "__main__":
        main();