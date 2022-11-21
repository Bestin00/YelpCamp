const express=require('express');
const router=express.Router({mergeParams:true});
const catchAsync=require('../utils/catchAsync');
const {reviewSchema}=require('../schemas.js');
const Review=require('../models/review');
const Campground = require('../models/campground');
const reviews=require('../controllers/reviews')
const ExpressError=require('../utils/ExpressError');
const {validateReview,isLoggedIn,isReviewAuthor}=require('../middleware')

const validateCampground=(req,res,next)=>{//MiddleWare
    const {error}=campgroundSchema.validate(req.body);
    if(error){
        const msg=error.details.map(el=>el.message).join(',')
        throw new ExpressError(msg,400);
    }else{
        next();
    }
}



router.post('/',isLoggedIn,validateReview,catchAsync(reviews.createReview));

router.delete('/:reviewId',isLoggedIn,isReviewAuthor,catchAsync(reviews.deleteReview));

module.exports=router;