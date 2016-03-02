#!/usr/bin/env bash

# select the virtual environment
ls ${PWD}
cd tempest
source .venv/bin/activate

pip install junitxml

exec testr last --subunit | ./.venv/bin/subunit-trace > report_trace.txt
exec testr last --subunit | ./.venv/bin/subunit-2to1 > report_results.txt
exec testr last --subunit | ./.venv/bin/subunit2junitxml > report_junit.xml

./.venv/bin/subunit2html report_results.txt test_results.html

# exit the virtual environment
deactivate