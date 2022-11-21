const Review=require('../models/review');
const Campground = require('../models/campground');


module.exports.createReview=async(req,res)=>{
    const campground= await Campground.findById(req.params.id)
    const review=new Review(req.body.review);
    review.author=req.user._id;
    campground.reviews.push(review);
    await review.save();
    await campground.save();
    req.flash('success','Created new review!')
    res.redirect(`/campgrounds/${campground._id}`)
}


module.exports.deleteReview=async(req,res)=>{
    const {id,reviewId}=req.params;
    await Campground.findByIdAndUpdate(id,{$pull:{reviews:reviewId}});//$pull its an operator its going to reviewId and pull anything with id out of it
    await Review.findByIdAndDelete(req.params.reviewId);
    req.flash('success','Successfully Deleted Review')
    res.redirect(`/campgrounds/${id}`);
}