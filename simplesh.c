// Miguel Medina Rodriguez - miguel.medina1@um.es - 48737352F
// Jose Ramon Martinez-Carbonell Martin - joseramon.martinez2@um.es - 48705846B
// Grupo 2.2

// Shell `simplesh`
// Macro para nftw
#define _XOPEN_SOURCE 500

#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <ftw.h>
#include <signal.h>

// Libreadline
#include <readline/history.h>
#include <readline/readline.h>

// Tipos presentes en la estructura `cmd`, campo `type`.
#define EXEC 1
#define REDIR 2
#define PIPE 3
#define LIST 4
#define BACK 5

#define MAXARGS 15
#define MAX_PATH_LENGTH 64
#define TAM_BUFFER_SIZE 128

// Estructuras
// -----

// La estructura `cmd` se utiliza para almacenar la información que
// servirá al shell para guardar la información necesaria para
// ejecutar las diferentes tipos de órdenes (tuberías, redirecciones,
// etc.)
//
// El formato es el siguiente:
//
//     |----------+--------------+--------------|
//     | (1 byte) | ...          | ...          |
//     |----------+--------------+--------------|
//     | type     | otros campos | otros campos |
//     |----------+--------------+--------------|
//
// Nótese cómo las estructuras `cmd` comparten el primer campo `type`
// para identificar el tipo de la estructura, y luego se obtendrá un
// tipo derivado a través de *casting* forzado de tipo. Se obtiene así
// un polimorfismo básico en C.
struct cmd {
  int type;
};

// Ejecución de un comando con sus parámetros
struct execcmd {
  int type;
  char *argv[MAXARGS];
  char *eargv[MAXARGS];
};

// Ejecución de un comando de redirección
struct redircmd {
  int type;
  struct cmd *cmd;
  char *file;
  char *efile;
  int mode;
  int fd;
};

// Ejecución de un comando de tubería
struct pipecmd {
  int type;
  struct cmd *left;
  struct cmd *right;
};

// Lista de órdenes
struct listcmd {
  int type;
  struct cmd *left;
  struct cmd *right;
};

// Tarea en segundo plano (background) con `&`.
struct backcmd {
  int type;
  struct cmd *cmd;
};

//********* BOLETIN 2 Implementación PWD        *********
void run_pwd() {
  // Directorio de trabajo
  extern int errno;
  char *dir = NULL;
  int i = 1;
  do {
    errno = 0;
    dir = realloc(dir, MAX_PATH_LENGTH * i);
    if (dir == NULL) {
      perror("malloc");
      exit(EXIT_FAILURE);
    }
    getcwd(dir, MAX_PATH_LENGTH * i);
    if (errno != 0 && errno != ERANGE) {
      perror("getcwd");
      exit(EXIT_FAILURE);
    }
    i++;
  } while (errno == ERANGE);

  fprintf(stderr, "%s", "simplesh: pwd: ");
  fprintf(stdout, "%s\n", dir);
  free(dir);
  exit(EXIT_SUCCESS);
}

//********* BOLETIN 2 Implementación EXIT       *********
void run_exit() { exit(EXIT_SUCCESS); }

//********* BOLETIN 2 Implementación CD         *********
void run_cd(char *dir) {
  int codEjecucion = 0;
  if (dir == NULL) {
    codEjecucion = chdir(getenv("HOME"));
  } else {
    codEjecucion = chdir(dir);
  }
  if (codEjecucion == -1) {
    perror("chdir");
  }
}

//********* BOLETIN 3 Función auxiliar          *********
char *get_current_time(const char *format) {
  static char buf[TAM_BUFFER_SIZE];
  time_t t;
  struct tm *tm;
  size_t s;

  t = time(NULL);
  if (t == -1) {
    perror("time");
    exit(EXIT_FAILURE);
  }
  tm = localtime(&t);
  if (tm == NULL) {
    fprintf(stderr, "%s", "ERROR función localtime. \n");
    exit(EXIT_FAILURE);
  }

  // Si el formato es NULL le asigna uno por defecto
  s = strftime(buf, TAM_BUFFER_SIZE, (format != NULL) ? format : " %c (%Z)",
               tm);

  return (s == 0) ? NULL : buf;
}

//********* BOLETIN 3 Implementación TEE        *********
void run_tee(char *argv[]) {
  // Cuenta de los argumentos (El primero es el nombre)
  int argc = 0;
  while (argv[argc] != NULL) {
    argc++;
  }
  // Flags de creación y lectura/escritura
  int flags = O_CREAT | O_RDWR | O_TRUNC;

  int parametros = 0;
  char ch;
  while ((ch = getopt(argc, argv, "ah")) != -1) {
    switch (ch) {
    case 'a':
      // Añadimos el flag para que añada al final con OR y quitamos el de TRUNC
      // con XOR
      flags = flags ^ O_TRUNC;
      flags = flags | O_APPEND;
      break;
    case 'h':
      printf("Uso: tee [-h] [-a] [FICHERO]...\n\tCopia stdin a cada FICHERO y "
             "a stdout.\n\t");
      printf("Opciones :\n\t-a Añade al final de cada FICHERO\n\t-h help\n");
      exit(EXIT_SUCCESS);
      break;

    case '?':
    default:
      printf("Argumento desconocido. Comando `tee -h` para más información.\n");
      exit(1);
      break;
    }
    parametros++;
  }

  // Leemos los descriptores de fichero incluyendo la entrada estándar y los
  // metemos en un array
  int *descriptores = malloc(sizeof(int) * (argc - parametros + 1));
  for (int i = parametros; i < argc; i++) {
    int fd = 0;
    if (i == parametros) {
      // Escribir en la salida estándar en la primera iteración
      fd = STDOUT_FILENO;
    } else {
      // Permisos en caso de creación del fichero
      mode_t modo_creacion = 0777;
      fd = open(argv[i], flags, modo_creacion);
    }
    descriptores[i] = fd;
  }

  // Acordamos este tamaño de buffer lo suficientemente grande
  int BUFFERSIZE = 1024;
  char *buff = malloc(sizeof(char) * BUFFERSIZE);

  int bytes_leidos = 0;
  int total_bytes_escritos = 0;
  int totalficheros = 0;

  while ((bytes_leidos = read(STDIN_FILENO, buff, BUFFERSIZE))) {
    // Tratamiento de error de read
    if (bytes_leidos == -1) {
      perror("read");
      free(buff);
      exit(EXIT_FAILURE);
    }

    // Manejo de los ficheros
    for (int i = parametros; i < argc; i++) {
      int fd = descriptores[i];
      if (fd != -1) {
        int bytes_escritos = write(fd, buff, bytes_leidos);

        if (bytes_escritos == -1) {
          perror("write");
          free(descriptores);
          free(buff);
          exit(EXIT_FAILURE);
        }

        // Este bloque es para el apartado opcional
        if (fd == STDOUT_FILENO) {
          total_bytes_escritos += bytes_escritos;
        }

        if (fd != STDOUT_FILENO && fsync(fd) == -1) {
          perror("fsync");
          free(descriptores);
          free(buff);
          exit(EXIT_FAILURE);
        }
      }
    }
  }

  // Cerramos los descriptores de fichero menos STDIN y realizamos la cuenta de
  // ficheros para la entrada al LOG
  for (int i = parametros + 1; i < argc; i++) {
    if (descriptores[i] != -1) {
      totalficheros++;
      close(descriptores[i]);
    }
  }

  // Liberamos la memoria del array de descriptores y el buffer en caso de que
  // todo haya ido bien
  free(descriptores);
  free(buff);

  // Parte opcional FICHERO DE LOG
  pid_t pid = getpid();
  uid_t euid = geteuid();
  char *current_time = get_current_time("%F %T");
  char *ruta_log = getenv("HOME");
  strcat(ruta_log, "/.tee.log");

  int flags_log = O_RDWR | O_APPEND | O_CREAT;
  int fd_log = open(ruta_log, flags_log, 0777);
  if (fd_log == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  if (fd_log != -1) {
    // Tamaño fijo suficientemente grande del buffer del log
    int total_bytes_log = 128;
    char *buff_log = malloc(sizeof(char) * total_bytes_log);

    // Copiamos la entrada en el buffer
    sprintf(buff_log, "%s:PID %d:EUID %d:%d byte(s):%d file(s)\n", current_time,
            pid, euid, total_bytes_escritos, totalficheros);
    int log_len = strlen(buff_log);

    // Escritura de la entrada del log
    int bytes_log = write(fd_log, buff_log, log_len);

    if (bytes_log == -1) {
      perror("write");
      free(buff_log);
      free(buff);
      exit(EXIT_FAILURE);
    }
    if (fsync(fd_log) == -1) {
      perror("fsync");
      free(buff_log);
      free(buff);
      exit(EXIT_FAILURE);
    }
    free(buff_log);
  }
  exit(EXIT_SUCCESS);
}

//********* BOLETIN 4 Variables globales        *********
int bytes_nftw = 0;
int flag_t = 0;
int flag_v = 0;
int flag_b = 0;
// Entero de 64 bits
long long int size_comp = 0;

// Función auxiliar para imprimir la información cuando activamos -v
void print_info(int level, const char *name, int n_read) {
  for (int i = 0; i < level; i++) {
    printf("\t");
  }
  printf("%s", name);
  if (n_read > 0) {
    printf(": %d\n", n_read);
  } else {
    printf("\n");
  }
}

//********* BOLETIN 4 Función auxiliar          *********
int list(const char *name, const struct stat *status, int type,
         struct FTW *ftwbuf) {
  if (type == FTW_NS) {
    return 0;
  }
  if (type == FTW_F) {
    int leidos = 0;
    if (flag_b) {
      leidos = status->st_blocks * 512;
    } else {
      leidos = status->st_size;
    }
    if (flag_t) {
      if (size_comp > 0) {
        if (leidos < size_comp) {
          bytes_nftw += leidos;
          if (flag_v) {
            print_info(ftwbuf->level, name, leidos);
          }
        }
      } else {
        if (leidos > llabs(size_comp)) {
          bytes_nftw += leidos;
          if (flag_v) {
            print_info(ftwbuf->level, name, leidos);
          }
        }
      }
    } else {
      bytes_nftw += leidos;
      if (flag_v) {
        print_info(ftwbuf->level, name, leidos);
      }
    }
  } else {
    if (flag_v) {
      print_info(ftwbuf->level, name, 0);
    }
  }

  return 0;
}

//********* BOLETIN 4 Implementación DU         *********
void run_du(char *argv[]) {
  // Cuenta de los argumentos (El primero es el nombre)
  int argc = 0;
  while (argv[argc] != NULL) {
    argc++;
  }

  // El primer parámetro es el nombre
  int parametros = 0;

  char ch;
  while ((ch = getopt(argc, argv, "hbt:v")) != -1) {
    switch (ch) {
    case 'b':
      flag_b = 1;
      parametros++;
      break;
    case 't':
      size_comp = atoll(optarg);

      if (size_comp == 0) {
        printf("Después de -t debe ir un entero con/sin signo válido distinto "
               "de 0.\n");
      } else {
        flag_t = 1;
      }
      // Aumentamos en 2 porque después de -t se espera un número y no hay que
      // procesarlo como parámentro
      parametros += 2;
      break;
    case 'v':
      flag_v = 1;
      parametros++;
      break;
    case 'h':
      printf("Uso: du [-h] [-b] [-t SIZE] [-v] [FICHERO|DIRECTORIO]...\nPara "
             "cada fichero, imprime su tamaño.\n");
      printf("Para cada directorio, imprime la suma de los tamaños de todos "
             "los ficheros de todos sus subdirectorios.\n");
      printf("\tOpciones :\n\t-b Imprime el tamaño ocupado en disco por todos "
             "los bloques del fichero.\n");
      printf("\t-t SIZE Excluye todos los ficheros más pequeños que SIZE "
             "bytes, si es positivo, o más grandes que SIZE bytes, si es "
             "negativo cuando se procesa un directorio.\n");
      printf("\t-v Imprime el tamaño de todos y cada uno de los ficheros "
             "cuando se procesa un directorio.\n");
      printf("\t-h help\n");
      printf("Nota: todos los tamaños estan expresados en bytes.\n");
      exit(EXIT_SUCCESS);
      break;
    case '?':
    default:
      printf("Argumento desconocido. Comando `du -h` para más información.\n");
      exit(1);
      break;
    }
  }

  if (argc < 2) {
    // Se llama a nftw con el directorio "."
    int flags_nftw = 0;
    nftw(".", list, 20, flags_nftw);

    printf("(D) %s: %d\n", ".", bytes_nftw);
    // Reseteamos la variable global
    bytes_nftw = 0;
  } else {
    // Le sumamos 1 a $parametros para ignorar el nombre del programa
    for (int i = parametros + 1; i < argc; i++) {
      struct stat path_stat;
      int error_stat = stat(argv[i], &path_stat);

      if (error_stat == -1) {
        // Reseteamos el modo para ignorar el argumento no válido
        path_stat.st_mode = 0;
      }

      if (S_ISREG(path_stat.st_mode)) { // Si es fichero se usa stat
        int tamano_fic = 0;
        if (flag_b) {
          // Tamaño de los bloques en disco (se múltiplica el número de bloques
          // por 512 que es los bytes que ocupa un bloque)
          tamano_fic = path_stat.st_blocks * 512;
        } else {
          // Tamaño en bytes del fichero
          tamano_fic = path_stat.st_size;
        }
        printf("(F) %s: %d\n", argv[i], tamano_fic);

      } else if (S_ISDIR(path_stat.st_mode)) { // Si es directorio se usa nftw

        int flags_nftw = 0;
        nftw(argv[i], list, 20, flags_nftw);
        printf("(D) %s: %d\n", argv[i], bytes_nftw);

        // Reseteamos la variable global
        bytes_nftw = 0;
      } else { // Si no es ninguno de los dos tipos se ignora
        printf("El argumento %s no es ni un fichero ni un directorio.\n",
               argv[i]);
      }
    }
  }
  // Reseteamos los valores para una próxima ejecución
  bytes_nftw = flag_t = flag_v = flag_b = 0;
  size_comp = 0LL;
  exit(EXIT_SUCCESS);
}

//********* BOLETIN 5 Variables globales        *********
struct timespec timeout;
int sigchld_counter = 0;

//********* BOLETIN 5 Manejadores para SIGCHLD, SIGUSR1 y SIGUSR2 *********
void sigchld_handler(int signal) {
  if (signal == SIGCHLD) {
    sigchld_counter++;
  }
}

void sigusr_handler(int signal) {
  if (signal == SIGUSR1) {
    timeout.tv_sec += 5;
  } else if (signal == SIGUSR2) {
    if (timeout.tv_sec <= 5) {
      timeout.tv_sec = 0;
    } else {
      timeout.tv_sec -= 5;
    }
  }
}

//********* BOLETIN 5 Procedimiento encargado de realizar la espera para SIGCHLD
//*********
void wait_chld_signal(int pid) {
  sigset_t sigchild;
  if ((sigemptyset(&sigchild) == -1) || (sigaddset(&sigchild, SIGCHLD) == -1)) {
    fprintf(stderr, "Failed to initialize the signal mask\n");
    exit(EXIT_FAILURE);
  }

  do {
    int signal = sigtimedwait(&sigchild, NULL, &timeout);
    if (signal < 0) {
      if (errno == EINTR) {
        // Interrupcion por una señal distinta a SIGCHLD
        continue;
      } else if (errno == EAGAIN) {
        fprintf(stderr, "\nsimplesh: [%d] Matado hijo con PID %d\n",
                sigchld_counter, pid);
        kill(pid, SIGKILL);
        // Reseteamos errno
        errno = 0;
      } else {
        perror("sigtimedwait");
        exit(EXIT_FAILURE);
      }
    }
    // En otro caso dejamos de esperar porque el proceso se ha ejecutado
    // correctamente y no ha superado el timeout
    break;
  } while (1);
}

//********* BOLETIN 5 Asignación de los bloqueos y manejadores a las señales
//*********
void block_signals() {
  // Establecemos el valor inicial del timeout
  timeout.tv_sec = 5;
  timeout.tv_nsec = 0;

  struct sigaction sa_sigchld;
  memset(&sa_sigchld.sa_flags, 0, sizeof(int));
  sa_sigchld.sa_handler = sigchld_handler;
  sigemptyset(&sa_sigchld.sa_mask);

  // Le ponemos el manejador a SIGCHLD
  if (sigaction(SIGCHLD, &sa_sigchld, NULL) == -1) {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }

  sigset_t blocked_signals;
  if ((sigemptyset(&blocked_signals) == -1) ||
      (sigaddset(&blocked_signals, SIGINT) == -1)) {
    fprintf(stderr, "Failed to initialize the signal mask\n");
    exit(EXIT_FAILURE);
  }

  if (sigprocmask(SIG_BLOCK, &blocked_signals, NULL) == -1) {
    perror("sigprocmask");
    exit(EXIT_FAILURE);
  }

  // Parte opcional del manejo de señales
  // Asignamos el manejador a SIGUSR1 y SIGUSR2
  struct sigaction sa_sigusr;
  memset(&sa_sigusr.sa_flags, 0, sizeof(int));
  sa_sigusr.sa_handler = sigusr_handler;
  sigemptyset(&sa_sigusr.sa_mask);

  if (sigaction(SIGUSR1, &sa_sigusr, NULL) == -1 ||
      sigaction(SIGUSR2, &sa_sigusr, NULL) == -1) {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }
}

// Declaración de funciones necesarias
int fork1(void); // Fork but panics on failure.
void panic(char *);
struct cmd *parse_cmd(char *);

// Declaración de las funciones de comandos internos
int run_internal_cmd(struct cmd *cmd);
int run_father_cmd(struct cmd *cmd);

// Ejecuta un `cmd`. Nunca retorna, ya que siempre se ejecuta en un
// hijo lanzado con `fork()`.
void run_cmd(struct cmd *cmd) {
  int p[2];
  struct backcmd *bcmd;
  struct execcmd *ecmd;
  struct listcmd *lcmd;
  struct pipecmd *pcmd;
  struct redircmd *rcmd;

  if (cmd == 0)
    exit(0);

  switch (cmd->type) {
  default:
    panic("run_cmd");

  // Ejecución de una única orden.
  case EXEC:
    ecmd = (struct execcmd *)cmd;
    if (ecmd->argv[0] == 0)
      exit(0);

    int father_code = run_father_cmd(cmd);
    int internal_code = run_internal_cmd(cmd);

    // Solo se hace exec si no es comando interno
    if (father_code < 0 && internal_code < 0) {
      execvp(ecmd->argv[0], ecmd->argv);

      // Si se llega aquí algo falló
      fprintf(stderr, "exec %s failed\n", ecmd->argv[0]);
      exit(1);
    }
    break;
  case REDIR:
    rcmd = (struct redircmd *)cmd;
    close(rcmd->fd);
    if (open(rcmd->file, rcmd->mode, S_IRWXU) < 0) {
      fprintf(stderr, "open %s failed\n", rcmd->file);
      exit(1);
    }
    run_cmd(rcmd->cmd);
    break;

  case LIST:
    lcmd = (struct listcmd *)cmd;

    if (fork1() == 0)
      run_cmd(lcmd->left);

    wait(NULL);

    run_cmd(lcmd->right);
    break;

  case PIPE:
    pcmd = (struct pipecmd *)cmd;
    if (pipe(p) < 0)
      panic("pipe");

    // Ejecución del hijo de la izquierda
    if (fork1() == 0) {
      close(1);
      dup(p[1]);
      close(p[0]);
      close(p[1]);
      run_cmd(pcmd->left);
    }

    // Ejecución del hijo de la derecha
    if (fork1() == 0) {
      close(0);
      dup(p[0]);
      close(p[0]);
      close(p[1]);
      run_cmd(pcmd->right);
    }
    close(p[0]);
    close(p[1]);

    // Esperar a ambos hijos
    wait(NULL);
    wait(NULL);
    break;

  case BACK:
    bcmd = (struct backcmd *)cmd;
    if (fork1() == 0)
      run_cmd(bcmd->cmd);
    break;
  }

  // Salida normal, código 0.
  exit(0);
}

// Muestra un *prompt* y lee lo que el usuario escribe usando la
// librería readline. Ésta permite almacenar en el historial, utilizar
// las flechas para acceder a las órdenes previas, búsquedas de
// órdenes, etc.
//
char *getcmd() {
  char *buf;
  uid_t uid = getuid();

  // ********** BOLETIN 2 Implementación del PROMPT **********
  // Nombre de usuario
  struct passwd *pw = getpwuid(uid);
  if (pw == NULL) {
    perror("getpwuid");
    exit(EXIT_FAILURE);
  }
  char *user_name = pw->pw_name;

  // Directorio de trabajo
  extern int errno;
  char *dir = NULL;
  int i = 1;
  do {
    errno = 0;
    dir = realloc(dir, MAX_PATH_LENGTH * i);
    if (dir == NULL) {
      perror("malloc");
      exit(EXIT_FAILURE);
    }
    getcwd(dir, MAX_PATH_LENGTH * i);
    if (errno != 0 && errno != ERANGE) {
      perror("getcwd");
      exit(EXIT_FAILURE);
    }
    i++;
  } while (errno == ERANGE);
  char *directory = basename(dir);

  char *prompt = malloc(sizeof(char) * MAX_PATH_LENGTH * i);

  if (prompt == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  int salida_bytes =
      snprintf(prompt, MAX_PATH_LENGTH * i, "%s@%s$ ", user_name, directory);
  if (salida_bytes < 0) {
    fprintf(stderr, "Error de la función snprintf\n");
    exit(EXIT_FAILURE);
  }
  // Lee la entrada del usuario y escribe el prompt en pantalla.
  buf = readline(prompt);

  // Si el usuario ha escrito algo, almacenarlo en la historia.
  if (buf && strcmp("", buf)) {
    add_history(buf);
  }

  free(dir);
  free(prompt);

  return buf;
}

int run_internal_cmd(struct cmd *command) {
  int codigo = -1;
  if (command->type == EXEC) {
    struct execcmd *ecmd = (struct execcmd *)command;
    if (ecmd->argv[0] != 0) {
      char *str_cmd = ecmd->argv[0];
      if (!strcmp(str_cmd, "pwd")) {
        run_pwd();
        codigo = 1;
      } else if (!strcmp(str_cmd, "tee")) {
        run_tee(ecmd->argv);
        codigo = 2;
      } else if (!strcmp(str_cmd, "du")) {
        run_du(ecmd->argv);
        codigo = 3;
      }
    }
  }
  return codigo;
}
int run_father_cmd(struct cmd *command) {
  int codigo = -1;
  if (command->type == EXEC) {
    struct execcmd *ecmd = (struct execcmd *)command;
    if (ecmd->argv[0] != 0) {
      char *str_cmd = ecmd->argv[0];
      if (!strcmp(str_cmd, "cd")) {
        run_cd(ecmd->argv[1]);
        codigo = 0;
      } else if (!strcmp(str_cmd, "exit")) {
        run_exit();
      }
    }
  }
  return codigo;
}

// Función `main()`.
// ----

int main(void) {
  char *buf;

  // Llamada a la función que bloquea las señales
  block_signals();

  // Bucle de lectura y ejecución de órdenes.
  while (NULL != (buf = getcmd())) {
    struct cmd *command = parse_cmd(buf);
    int father_cmd = run_father_cmd(command);
    if (father_cmd != 0) {
      int pid = fork1();
      if (pid == 0) {
        run_cmd(command);
      }
      wait_chld_signal(pid);

      // Esperar al hijo creado
      int status;
      if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        exit(EXIT_FAILURE);
      }
    }
    free((void *)buf);
    free(command);
  }
  return 0;
}

void panic(char *s) {
  fprintf(stderr, "%s\n", s);
  exit(-1);
}

// Como `fork()` salvo que muestra un mensaje de error si no se puede
// crear el hijo.
int fork1(void) {
  int pid;
  pid = fork();
  if (pid == -1)
    panic("fork");
  return pid;
}

// Constructores de las estructuras `cmd`.
// ----

// Construye una estructura `EXEC`.
struct cmd *execcmd(void) {
  struct execcmd *cmd;

  cmd = malloc(sizeof(*cmd));
  memset(cmd, 0, sizeof(*cmd));
  cmd->type = EXEC;
  return (struct cmd *)cmd;
}

// Construye una estructura de redirección.
struct cmd *redircmd(struct cmd *subcmd, char *file, char *efile, int mode,
                     int fd) {
  struct redircmd *cmd;

  cmd = malloc(sizeof(*cmd));
  memset(cmd, 0, sizeof(*cmd));
  cmd->type = REDIR;
  cmd->cmd = subcmd;
  cmd->file = file;
  cmd->efile = efile;
  cmd->mode = mode;
  cmd->fd = fd;
  return (struct cmd *)cmd;
}

// Construye una estructura de tubería (*pipe*).
struct cmd *pipecmd(struct cmd *left, struct cmd *right) {
  struct pipecmd *cmd;

  cmd = malloc(sizeof(*cmd));
  memset(cmd, 0, sizeof(*cmd));
  cmd->type = PIPE;
  cmd->left = left;
  cmd->right = right;
  return (struct cmd *)cmd;
}

// Construye una estructura de lista de órdenes.
struct cmd *listcmd(struct cmd *left, struct cmd *right) {
  struct listcmd *cmd;

  cmd = malloc(sizeof(*cmd));
  memset(cmd, 0, sizeof(*cmd));
  cmd->type = LIST;
  cmd->left = left;
  cmd->right = right;
  return (struct cmd *)cmd;
}

// Construye una estructura de ejecución que incluye una ejecución en
// segundo plano.
struct cmd *backcmd(struct cmd *subcmd) {
  struct backcmd *cmd;

  cmd = malloc(sizeof(*cmd));
  memset(cmd, 0, sizeof(*cmd));
  cmd->type = BACK;
  cmd->cmd = subcmd;
  return (struct cmd *)cmd;
}

// Parsing
// ----

const char whitespace[] = " \t\r\n\v";
const char symbols[] = "<|>&;()";

// Obtiene un *token* de la cadena de entrada `ps`, y hace que `q` apunte a
// él (si no es `NULL`).
int gettoken(char **ps, char *end_of_str, char **q, char **eq) {
  char *s;
  int ret;

  s = *ps;
  while (s < end_of_str && strchr(whitespace, *s))
    s++;
  if (q)
    *q = s;
  ret = *s;
  switch (*s) {
  case 0:
    break;
  case '|':
  case '(':
  case ')':
  case ';':
  case '&':
  case '<':
    s++;
    break;
  case '>':
    s++;
    if (*s == '>') {
      ret = '+';
      s++;
    }
    break;

  default:
    // El caso por defecto (no hay caracteres especiales) es el de un
    // argumento de programa. Se retorna el valor `'a'`, `q` apunta al
    // mismo (si no era `NULL`), y `ps` se avanza hasta que salta todos
    // los espacios **después** del argumento. `eq` se hace apuntar a
    // donde termina el argumento. Así, si `ret` es `'a'`:
    //
    //     |-----------+---+---+---+---+---+---+---+---+---+-----------|
    //     | (espacio) | a | r | g | u | m | e | n | t | o | (espacio) |
    //     |-----------+---+---+---+---+---+---+---+---+---+-----------|
    //                   ^                                   ^
    //                   |q                                  |eq
    //
    ret = 'a';
    while (s < end_of_str && !strchr(whitespace, *s) && !strchr(symbols, *s))
      s++;
    break;
  }

  // Apuntar `eq` (si no es `NULL`) al final del argumento.
  if (eq)
    *eq = s;

  // Y finalmente saltar los espacios en blanco y actualizar `ps`.
  while (s < end_of_str && strchr(whitespace, *s))
    s++;
  *ps = s;

  return ret;
}

// La función `peek()` recibe un puntero a una cadena, `ps`, y un final de
// cadena, `end_of_str`, y un conjunto de tokens (`toks`). El puntero
// pasado, `ps`, es llevado hasta el primer carácter que no es un espacio y
// posicionado ahí. La función retorna distinto de `NULL` si encuentra el
// conjunto de caracteres pasado en `toks` justo después de los posibles
// espacios.
int peek(char **ps, char *end_of_str, char *toks) {
  char *s;

  s = *ps;
  while (s < end_of_str && strchr(whitespace, *s))
    s++;
  *ps = s;

  return *s && strchr(toks, *s);
}

// Definiciones adelantadas de funciones.
struct cmd *parse_line(char **, char *);
struct cmd *parse_pipe(char **, char *);
struct cmd *parse_exec(char **, char *);
struct cmd *nulterminate(struct cmd *);

// Función principal que hace el *parsing* de una línea de órdenes dada por
// el usuario. Llama a la función `parse_line()` para obtener la estructura
// `cmd`.
struct cmd *parse_cmd(char *s) {
  char *end_of_str;
  struct cmd *cmd;

  end_of_str = s + strlen(s);
  cmd = parse_line(&s, end_of_str);

  peek(&s, end_of_str, "");
  if (s != end_of_str) {
    fprintf(stderr, "restante: %s\n", s);
    panic("syntax");
  }

  // Termina en `'\0'` todas las cadenas de caracteres de `cmd`.
  nulterminate(cmd);

  return cmd;
}

// *Parsing* de una línea. Se comprueba primero si la línea contiene alguna
// tubería. Si no, puede ser un comando en ejecución con posibles
// redirecciones o un bloque. A continuación puede especificarse que se
// ejecuta en segundo plano (con `&`) o simplemente una lista de órdenes
// (con `;`).
struct cmd *parse_line(char **ps, char *end_of_str) {
  struct cmd *cmd;

  cmd = parse_pipe(ps, end_of_str);
  while (peek(ps, end_of_str, "&")) {
    gettoken(ps, end_of_str, 0, 0);
    cmd = backcmd(cmd);
  }

  if (peek(ps, end_of_str, ";")) {
    gettoken(ps, end_of_str, 0, 0);
    cmd = listcmd(cmd, parse_line(ps, end_of_str));
  }

  return cmd;
}

// *Parsing* de una posible tubería con un número de órdenes.
// `parse_exec()` comprobará la orden, y si al volver el siguiente *token*
// es un `'|'`, significa que se puede ir construyendo una tubería.
struct cmd *parse_pipe(char **ps, char *end_of_str) {
  struct cmd *cmd;

  cmd = parse_exec(ps, end_of_str);
  if (peek(ps, end_of_str, "|")) {
    gettoken(ps, end_of_str, 0, 0);
    cmd = pipecmd(cmd, parse_pipe(ps, end_of_str));
  }

  return cmd;
}

// Construye los comandos de redirección si encuentra alguno de los
// caracteres de redirección.
struct cmd *parse_redirs(struct cmd *cmd, char **ps, char *end_of_str) {
  int tok;
  char *q, *eq;

  // Si lo siguiente que hay a continuación es una redirección...
  while (peek(ps, end_of_str, "<>")) {
    // La elimina de la entrada
    tok = gettoken(ps, end_of_str, 0, 0);

    // Si es un argumento, será el nombre del fichero de la
    // redirección. `q` y `eq` tienen su posición.
    if (gettoken(ps, end_of_str, &q, &eq) != 'a')
      panic("missing file for redirection");

    switch (tok) {
    case '<':
      cmd = redircmd(cmd, q, eq, O_RDONLY, 0);
      break;
    case '>':
      cmd = redircmd(cmd, q, eq, O_RDWR | O_CREAT | O_TRUNC, 1);
      break;
    case '+': // >>
      cmd = redircmd(cmd, q, eq, O_RDWR | O_CREAT | O_APPEND, 1);
      break;
    }
  }

  return cmd;
}

// *Parsing* de un bloque de órdenes delimitadas por paréntesis.
struct cmd *parse_block(char **ps, char *end_of_str) {
  struct cmd *cmd;

  // Esperar e ignorar el paréntesis
  if (!peek(ps, end_of_str, "("))
    panic("parse_block");
  gettoken(ps, end_of_str, 0, 0);

  // Parse de toda la línea hsta el paréntesis de cierre
  cmd = parse_line(ps, end_of_str);

  // Elimina el paréntesis de cierre
  if (!peek(ps, end_of_str, ")"))
    panic("syntax - missing )");
  gettoken(ps, end_of_str, 0, 0);

  // ¿Posibles redirecciones?
  cmd = parse_redirs(cmd, ps, end_of_str);

  return cmd;
}

// Hace en *parsing* de una orden, a no ser que la expresión comience por
// un paréntesis. En ese caso, se inicia un grupo de órdenes para ejecutar
// las órdenes de dentro del paréntesis (llamando a `parse_block()`).
struct cmd *parse_exec(char **ps, char *end_of_str) {
  char *q, *eq;
  int tok, argc;
  struct execcmd *cmd;
  struct cmd *ret;

  // ¿Inicio de un bloque?
  if (peek(ps, end_of_str, "("))
    return parse_block(ps, end_of_str);

  // Si no, lo primero que hay una línea siempre es una orden. Se
  // construye el `cmd` usando la estructura `execcmd`.
  ret = execcmd();
  cmd = (struct execcmd *)ret;

  // Bucle para separar los argumentos de las posibles redirecciones.
  argc = 0;
  ret = parse_redirs(ret, ps, end_of_str);
  while (!peek(ps, end_of_str, "|)&;")) {
    if ((tok = gettoken(ps, end_of_str, &q, &eq)) == 0)
      break;

    // Aquí tiene que reconocerse un argumento, ya que el bucle para
    // cuando hay un separador
    if (tok != 'a')
      panic("syntax");

    // Apuntar el siguiente argumento reconocido. El primero será la
    // orden a ejecutar.
    cmd->argv[argc] = q;
    cmd->eargv[argc] = eq;
    argc++;
    if (argc >= MAXARGS)
      panic("too many args");

    // Y de nuevo apuntar posibles redirecciones
    ret = parse_redirs(ret, ps, end_of_str);
  }

  // Finalizar las líneas de órdenes
  cmd->argv[argc] = 0;
  cmd->eargv[argc] = 0;

  return ret;
}

// Termina en NUL todas las cadenas de `cmd`.
struct cmd *nulterminate(struct cmd *cmd) {
  int i;
  struct backcmd *bcmd;
  struct execcmd *ecmd;
  struct listcmd *lcmd;
  struct pipecmd *pcmd;
  struct redircmd *rcmd;

  if (cmd == 0)
    return 0;

  switch (cmd->type) {
  case EXEC:
    ecmd = (struct execcmd *)cmd;
    for (i = 0; ecmd->argv[i]; i++)
      *ecmd->eargv[i] = 0;
    break;

  case REDIR:
    rcmd = (struct redircmd *)cmd;
    nulterminate(rcmd->cmd);
    *rcmd->efile = 0;
    break;

  case PIPE:
    pcmd = (struct pipecmd *)cmd;
    nulterminate(pcmd->left);
    nulterminate(pcmd->right);
    break;

  case LIST:
    lcmd = (struct listcmd *)cmd;
    nulterminate(lcmd->left);
    nulterminate(lcmd->right);
    break;

  case BACK:
    bcmd = (struct backcmd *)cmd;
    nulterminate(bcmd->cmd);
    break;
  }

  return cmd;
}

/*
 * Local variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 75
 * eval: (auto-fill-mode t)
 * End:
 */
