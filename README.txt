CyberGuard AI - Starter Image Forensics Dataset

This is an AUTOMATICALLY GENERATED SYNTHETIC STARTER DATASET.
It is intended to test the CyberGuard image pipeline, feature extractor,
training code, API upload flow, and UI.

It is NOT a production-quality forensic benchmark and should NOT be used
to claim real-world detection accuracy.

Classes:
- authentic
- manipulated

Manipulations:
- copy_move
- splice
- removal
- retouch
- recompression

Important:
The authentic/manipulated pair from the same source_group stays in the
same train/validation/test split to reduce source-image leakage.

For a real model, replace/augment this dataset with licensed/public
forensic datasets and keep an independent external test set.
