// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "cmd.h"
#include "utils.h"

#define READ 0
#define WRITE 1

#define PATH_MAX 4096

static bool shell_cd(word_t *dir) {
	char *path;

	if (!dir) {
		path = getenv("HOME");
		if (!path) {
			fprintf(stderr, "cd: HOME not set\n");
			return false;
		}
	} else {
		path = get_word(dir);
	}

	if (chdir(path) == -1) {
		fprintf(stderr, "cd: %s: No such file or directory\n", path);
		free(path);
		return false;
	}

	free(path);
	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void) {
	/* TODO: Execute exit/quit. */
	return SHELL_EXIT;
}

static int handle_cd_with_output(simple_command_t *s, char **argv) {
	int saved_stdout = -1, fd_out = -1;

	if (s->out) {
		char *output_file = get_word(s->out);

		saved_stdout = dup(STDOUT_FILENO);

		fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		DIE(fd_out < 0, "open output failed");
		dup2(fd_out, STDOUT_FILENO);
		close(fd_out);
		free(output_file);
	}

	shell_cd(s->params);

	if (saved_stdout != -1) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
	}

	free(argv);
	return 0;
}

static int handle_pwd_with_output(simple_command_t *s, char **argv) {
	int saved_stdout = -1, fd_out = -1;

	if (s->out) {
		char *output_file = get_word(s->out);

		saved_stdout = dup(STDOUT_FILENO);

		fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		DIE(fd_out < 0, "open output failed");
		dup2(fd_out, STDOUT_FILENO);
		close(fd_out);
		free(output_file);
	}

	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) != NULL) {
		printf("%s\n", cwd);
	} else {
		perror("pwd");
	}

	if (saved_stdout != -1) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
	}

	free(argv);
	return 0;
}

static void handle_input_redirection(simple_command_t *s) {
	int fd_in;

	if (s->in) {
		char *input_file = get_word(s->in);

		fd_in = open(input_file, O_RDONLY);
		DIE(fd_in < 0, "open input failed");
		dup2(fd_in, STDIN_FILENO);
		close(fd_in);
		free(input_file);
	}
}

static void handle_output_redirection(simple_command_t *s) {
	int fd_out;

	if (s->out) {
		char *output_file = get_word(s->out);

		if (!(s->io_flags & IO_OUT_APPEND)) {
			fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		} else {
			fd_out = open(output_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
		}

		DIE(fd_out < 0, "open output failed");
		dup2(fd_out, STDOUT_FILENO);
		close(fd_out);
		free(output_file);
	}
}

static void handle_error_redirection(simple_command_t *s) {
	int fd_err;

	if (s->err) {
		char *error_file = get_word(s->err);

		if (!(s->io_flags & IO_ERR_APPEND)) {
			fd_err = open(error_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		} else {
			fd_err = open(error_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
		}

		DIE(fd_err < 0, "open error output failed");
		dup2(fd_err, STDERR_FILENO);
		close(fd_err);
		free(error_file);
	}
}

// >&
static void handle_combined_output_error_redirection(simple_command_t *s) {
	if (s->out && s->err && strcmp(get_word(s->out), get_word(s->err)) == 0) {
		char *output_file = get_word(s->out);

		int fd_out_err = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		DIE(fd_out_err < 0, "open combined output failed");
		dup2(fd_out_err, STDOUT_FILENO);
		dup2(fd_out_err, STDERR_FILENO);
		close(fd_out_err);
		free(output_file);
	}
}

static void execute_command(char **argv) {
	execvp(argv[0], argv);
	perror("execvp failed");
	exit(EXIT_FAILURE);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father) {
	pid_t pid;
	int status, fd_in = -1, fd_out = -1;
	int saved_stdout = -1;
	char **argv;
	int size;

	argv = get_argv(s, &size);

	if (strcmp(argv[0], "cd") == 0) {
		return handle_cd_with_output(s, argv);
	}

	if (strcmp(argv[0], "pwd") == 0) {
		return handle_pwd_with_output(s, argv);
	}

	if (strcmp(argv[0], "exit") == 0 || strcmp(argv[0], "quit") == 0) {
		free(argv);
		return shell_exit();
	}

	// comenzi externe
	pid = fork();
	DIE(pid < 0, "fork failed");

	if (pid == 0) {
		handle_input_redirection(s);
		handle_output_redirection(s);
		handle_error_redirection(s);
		handle_combined_output_error_redirection(s);
		execute_command(argv);
	} else {
		waitpid(pid, &status, 0);
		free(argv);
		return WEXITSTATUS(status);
	}
}

static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
														command_t *father) {
	/* TODO: Execute cmd1 and cmd2 simultaneously. */

	pid_t pid1, pid2;

	pid1 = fork();
	if (pid1 == 0) {
		parse_command(cmd1, level + 1, father);
		exit(0);
	}

	pid2 = fork();
	if (pid2 == 0) {
		parse_command(cmd2, level + 1, father);
		exit(0);
	}

	waitpid(pid1, NULL, 0);
	waitpid(pid2, NULL, 0);

	return true;
}
// -------------------------------------------------------------
/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
												command_t *father) {
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */

	int fd[2];
	pid_t pid1, pid2;

	pipe(fd);
	pid1 = fork();

	if (pid1 == 0) { //proces copil 1
		close(fd[READ]); // 0
		dup2(fd[WRITE], STDOUT_FILENO);
		close(fd[WRITE]); // 1
		parse_command(cmd1, level + 1, father);
		exit(0);
	}

	pid2 = fork();

	if (pid2 == 0) { // proces copil 2
		close(fd[WRITE]);
		dup2(fd[READ], STDIN_FILENO);
		close(fd[READ]);
		parse_command(cmd2, level + 1, father);
		exit(0);
	}

	close(fd[READ]);
	close(fd[WRITE]);

	waitpid(pid1, NULL, 0);
	waitpid(pid2, NULL, 0);

	return true;
}

static int execute_sequential(command_t *cmd1, command_t *cmd2, int level,
															command_t *father) {
	int ret = parse_command(cmd1, level + 1, father);
	ret = parse_command(cmd2, level + 1, father);
	return ret;
}

static int execute_parallel(command_t *cmd1, command_t *cmd2, int level,
														command_t *father) {
	run_in_parallel(cmd1, cmd2, level + 1, father);
	return 0;
}

static int execute_conditional_zero(command_t *cmd1, command_t *cmd2, int level,
																		command_t *father) {
	int ret = parse_command(cmd1, level + 1, father);
	if (ret == 0) {
		ret = parse_command(cmd2, level + 1, father);
	}
	return ret;
}

static int execute_conditional_nonzero(command_t *cmd1, command_t *cmd2,
																			 int level, command_t *father) {
	int ret = parse_command(cmd1, level + 1, father);
	if (ret != 0) {
		ret = parse_command(cmd2, level + 1, father);
	}
	return ret;
}

static int execute_pipe(command_t *cmd1, command_t *cmd2, int level,
												command_t *father) {
	return run_on_pipe(cmd1, cmd2, level + 1, father);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father) {
	int ret = 0;

	if (!c)
		return -1;

	if (c->op == OP_NONE) {
		return parse_simple(c->scmd, level, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		ret = execute_sequential(c->cmd1, c->cmd2, level, c);
		break;

	case OP_PARALLEL: // &
		ret = execute_parallel(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_ZERO: // &&
		ret = execute_conditional_zero(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_NZERO: // ||
		ret = execute_conditional_nonzero(c->cmd1, c->cmd2, level, c);
		break;

	case OP_PIPE: // |
		ret = execute_pipe(c->cmd1, c->cmd2, level, c);
		break;

	default:
		ret = SHELL_EXIT;
		break;
	}

	return ret;
}
