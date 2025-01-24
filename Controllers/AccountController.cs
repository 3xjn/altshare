using System.ComponentModel.DataAnnotations;
using AltShare.Models;
using AltShare.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AltShare.Controllers
{
    [ApiController]
    [Route("/account")]
    public class AccountController : Controller
    {
        private readonly SharedAccountService _sharedService;

        public AccountController(SharedAccountService SharedService)
        {
            _sharedService = SharedService;
        }

        [Authorize]
        [HttpPost("upload")]
        public IActionResult UploadAccount(string email, string password, [FromBody] DecryptedSharedAccount account)
        {
            _sharedService.Create(email, password, new List<DecryptedSharedAccount> { account });
            return Ok();
        }
    }
}
