for dir in ./examples/*/
do
    dir=${dir%*/}
    rm $dir/*.txt $dir/*.bc $dir/*.ll $dir/*.pdf $dir/*.dot $dir/*.png $dir/*.o $dir/*.taint $dir/*.out
done
