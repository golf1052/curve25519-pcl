# curve25519-pcl

## This has been superseded by [curve25519-dotnet](https://github.com/signal-csharp/curve25519-dotnet)

Portable C# implementation of curve25519 (and ed25519 for signing/verification) based on https://github.com/WhisperSystems/curve25519-java.

## Usage
    PM> Install-Package curve25519-pcl

    using org.whispersystems.curve25519;
    // ...
    Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);

There are 2 implementations currently. One is a pure C#, "textbook" (aka written without any math optimization) version, and the other was ported from Google's C++ implementation of Curve25519 "donna" https://code.google.com/archive/p/curve25519-donna/.

This library supersedes https://github.com/langboost/curve25519-uwp , because the portable class library implementation runs in "traditional" as well as "modern" .NET environments. UWP was strictly for modern .NET environments, and there's really no reason now to choose it on new projects. It will stick around for posterity's sake.

## Further Reading
These implementation notes from DJB were very helpful in porting this from Java & C++ to C#.
https://cr.yp.to/ecdh.html


# License
Copyright 2016 langboost

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
