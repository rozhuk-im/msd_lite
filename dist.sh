#!/bin/sh

TAR=${2:-"tar"}

if [ $# -lt 1 ] ; then
	echo "Usage: dist.sh <filename> [tar_command]"
	exit 1
fi

FILE_NAME=$1
PREFIX=`basename $FILE_NAME | sed -e 's/\.tar.*$//'`

OUT=""
while true ; do
	__mktemp=`which mktemp`
	if [ F"$__mktemp" != "F" ] ; then
		OUT=`$__mktemp /tmp/files-XXXXXXXX`
		break
	else
		OUT="/tmp/files-`strings -7 /dev/urandom | head -1 | sed -e 's/[^[:alnum:]]//g'`"
	fi
	if [ ! -f "$OUT" ] ; then
		break
	fi
done

git ls-files > $OUT
SUBMODULES=`git submodule | cut -d ' ' -f 3`

for sub in $SUBMODULES ; do
	(cd $sub && git ls-files | sed -e "s|^|$sub/|" >> $OUT)
done

${TAR} -c --exclude='.[^/]*' --exclude='*.xz' --exclude='*.gz' --no-recursion --transform "s|^|$PREFIX/|" -a -T $OUT -v -f $FILE_NAME
rm -f $OUT
