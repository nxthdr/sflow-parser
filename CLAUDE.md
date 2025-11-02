To implement a new sFlow specification extension, follow these steps:

1. Read the specification document. You can find it on the `README.md`.
2. Implement the models in the `src/models` directory for the flows and counters records. Please keep the ordering of the models based on the (enterprise, format) tuple. Also, please include a docstring for each model with the specification XDR record definition. Stay as close as possible to the specification, keeping the field names, types (adapting for Rust) and order.
3. Implement the parser in the `src/parsers` directory. Please keep the ordering of the parsers based on the (enterprise, format) tuple.
4. Add unit tests in the `tests/unit` directory. Particularly, implement at minimum one test for each parser in the `tests/unit/comprehensive` directory.Please keep the ordering of the tests based on the (enterprise, format) tuple.
5. See if the integration tests need to be updated in the `tests/integration` directory.
6. Update the documentation in the `README.md` file, checking newly implemented specifications, and the newly implemented flow and counter records sections.
7. Add the specification in the `tests/validation/specs_validation.rs` file (in the `SFLOW_SPECS` constant). Please keep the ordering of the specifications based on the year.

To implement records that are not part of a spec (such as sFlow discussions), you can follow the plan above but skip the steps related to the specification validation.

To check that the implementation is correct, please run:

1. `make test` to validate the unit tests.
2. `make test-integration` to validate the integration tests.
3. `make specs-validate` to validate the implementation against the official sFlow specifications. If there is any warning, please check if is due to the implementation or the validation script. In any case, please fix the issue until there is no warning. Avoid doing exception to make the tests pass unless it is really justified and well documented. Also make sure that all of the newly added models are validated.
4. `make coverage` to validate the coverage of the implementation.

Finally, run `make fmt` and `make clippy` and `make build` to validate the code quality and build the project.
