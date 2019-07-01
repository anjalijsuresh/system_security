PROG_NAME=password_craker.c
EXEC_NAME=password_craker.out
PASS=training-passwd.txt
SHADOW=training-shadow.txt
DICT=top250.txt
OUTPUT=output.txt
default:
	gcc ${PROG_NAME} -o ${EXEC_NAME} -lcrypt
run:
	./${EXEC_NAME} -p ./${PASS} -s ./${SHADOW} -d ./${DICT} -o ${OUTPUT}
clean:
	rm ${EXEC_NAME}
