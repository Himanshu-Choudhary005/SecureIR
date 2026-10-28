# SecureIR: ML-Based Security Analysis of Intermediate Representation Before Code Generation

## Project Overview

SecureIR is a machine-learning-based security analysis project that examines C programs using LLVM Intermediate Representation (IR).

The system combines:

* LLVM IR generation using Clang
* IR feature extraction
* Random Forest classification
* Pattern-based static analysis
* Preliminary data-flow checks
* Combined security analysis reports

## Security Categories

* SAFE
* MEMORY_RISK
* INTEGER_RISK

## Technologies Used

* Python
* C
* Clang/LLVM
* Machine Learning
* scikit-learn
* pandas

## How to Run

1. Install Python and configure Clang/LLVM.

2. Install the required Python packages listed in `requirements.txt`.

3. Train the model if necessary:

   `python train_model.py`

4. Analyze a C program:

   `python secureir_analyzer.py path/to/program.c`

5. Evaluate the independent test dataset:

   `python run_independent_test.py`

6. Run combined evaluation:

   `python evaluate_combined.py`

## Evaluation

The current recorded results are:

* Leave-One-Out Cross-Validation accuracy: 85.2%
* Independent test accuracy: 83.33% on 12 test programs

These are preliminary results from a small dataset and should not be interpreted as guaranteed real-world vulnerability detection accuracy.

## Limitations

SecureIR performs preliminary security screening. Its ML predictions and static/data-flow findings are not proof that a program is secure or vulnerable. Results require manual review.

## Authors

-Himanshu Choudhary
-Annum Singh
