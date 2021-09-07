using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LongVision.Api.ViewModel
{
    public class RegisterVm
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PhoneNumber { get; set; }
        public string ImagePath { get; set; }
    }
}
