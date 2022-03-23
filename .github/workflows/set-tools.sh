
if [ -z "${{ env.VAR }}" ]; then
    echo 'VAR=\"${1}\"' >> $GITHUB_ENV
else
    echo 'VAR=${{ env.VAR }},\"${1}\"' >> $GITHUB_ENV
fi