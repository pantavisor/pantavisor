1. Run make to compile the application
2. The above command will output a binary "udevmap"
3. To run it under valgrind, 
    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./udevmap
