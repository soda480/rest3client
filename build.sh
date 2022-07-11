versions=( '3.7' '3.8' '3.9' '3.10' )
for version in "${versions[@]}";
do
    docker image build --target build-image --build-arg PYTHON_VERSION=$version -t rest3client:$version .
done