REBAR3=$(shell which rebar3)
ifeq ($(REBAR3),)
REBAR3=./rebar3
endif

all: compile

clean:
	@echo "Running rebar3 clean..."
	@$(REBAR3) clean -a

compile:
	@echo "Running rebar3 compile..."
	@$(REBAR3) as compile compile

eunit:
	@echo "Running rebar3 eunit..."
	@$(REBAR3) do eunit -cv

.PHONY: clean compile eunit
