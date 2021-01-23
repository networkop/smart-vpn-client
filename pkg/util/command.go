package util

import "os/exec"

type Command struct {
	Cmd *exec.Cmd
}

func NewCommand(bin string) *Command {

	return &Command{
		Cmd: exec.Command(bin),
	}
}

func (c *Command) With(args ...string) *Command {
	c.Cmd.Args = append(c.Cmd.Args, args...)
	return c
}

func (c *Command) Run() ([]byte, error) {
	return c.Cmd.CombinedOutput()
}
